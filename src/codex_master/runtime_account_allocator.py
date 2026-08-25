from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import Enum
from secrets import token_urlsafe
from threading import Lock
from typing import Protocol

from codex_master.agent_resolver import ResolutionDecision


class AllocationDenied(Exception):
    pass


class _OpaqueText(str):
    __slots__ = ()

    def __deepcopy__(self, _memo: object) -> object:
        raise TypeError("runtime account allocator internals are not serializable")

    def __reduce_ex__(self, _protocol: int) -> object:
        raise TypeError("runtime account allocator internals are not serializable")


class _RedactedNonSerializable:
    __slots__ = ()

    def __repr__(self) -> str:
        return f"<{type(self).__name__} redacted>"

    __str__ = __repr__

    def __reduce_ex__(self, _protocol: int) -> object:
        raise TypeError("runtime account allocator internals are not serializable")

    def _redact_text_fields(self, *field_names: str) -> None:
        for field_name in field_names:
            value = getattr(self, field_name)
            if type(value) is str:
                object.__setattr__(self, field_name, _OpaqueText(value))


@dataclass(frozen=True, slots=True, repr=False)
class ValidatedAllocationTicket(_RedactedNonSerializable):
    ticket_id: str
    resolution_decision: ResolutionDecision
    resolver_offer_generation: int
    policy_generation: int
    capability_binding_digest: str
    ledger_revision: int
    phase: str
    fencing_token: str

    def __post_init__(self) -> None:
        self._redact_text_fields(
            "ticket_id", "capability_binding_digest", "phase", "fencing_token"
        )


@dataclass(frozen=True, slots=True, repr=False)
class CapacityEvidence(_RedactedNonSerializable):
    ticket_id: str
    resolver_offer_generation: int
    policy_generation: int
    capability_binding_digest: str
    ledger_revision: int
    fencing_token: str
    provider_adapter_id: str
    capacity_units: int | None
    quota_units: int | None
    cost_units: int | None
    resource_units: int | None
    evidence_revision: int
    observed_at_utc: datetime
    expires_at_utc: datetime

    def __post_init__(self) -> None:
        self._redact_text_fields(
            "ticket_id",
            "capability_binding_digest",
            "fencing_token",
            "provider_adapter_id",
        )


@dataclass(frozen=True, slots=True, repr=False)
class TransactionEvidence(_RedactedNonSerializable):
    ticket_id: str
    lease_id: str
    lease_revision: int
    ledger_revision: int
    capability_binding_digest: str
    account_binding_digest: str
    profile_binding_digest: str
    provider_adapter_id: str
    fencing_token: str
    phase: str

    def __post_init__(self) -> None:
        self._redact_text_fields(
            "ticket_id",
            "lease_id",
            "capability_binding_digest",
            "account_binding_digest",
            "profile_binding_digest",
            "provider_adapter_id",
            "fencing_token",
            "phase",
        )


@dataclass(frozen=True, slots=True, repr=False)
class AccountReservation(_RedactedNonSerializable):
    reservation_id: str
    account_binding_digest: str
    profile_binding_digest: str
    provider_adapter_id: str
    lease_revision: int
    evidence_revision: int
    fencing_token: str
    expires_at_utc: datetime

    def __post_init__(self) -> None:
        self._redact_text_fields(
            "reservation_id",
            "account_binding_digest",
            "profile_binding_digest",
            "provider_adapter_id",
            "fencing_token",
        )


@dataclass(frozen=True, slots=True, repr=False)
class CredentialLease(_RedactedNonSerializable):
    lease_id: str
    account_binding_digest: str
    profile_binding_digest: str
    provider_adapter_id: str
    lease_revision: int
    expires_at_utc: datetime

    def __post_init__(self) -> None:
        self._redact_text_fields(
            "lease_id",
            "account_binding_digest",
            "profile_binding_digest",
            "provider_adapter_id",
        )


class CapabilityProviderAdapter(Protocol):
    adapter_id: str

    def reserve_capability_atomically(
        self, capability_binding_digest: str, capacity_evidence: CapacityEvidence
    ) -> AccountReservation | None: ...

    def release_reservation(self, reservation: AccountReservation) -> None: ...


class LeaseState(str, Enum):
    RESERVED = "reserved"
    REVOKED = "revoked"


@dataclass(frozen=True, slots=True, repr=False)
class _LeaseRecord(_RedactedNonSerializable):
    lease: CredentialLease
    reservation: AccountReservation
    ticket_id: str
    ledger_revision: int
    capability_binding_digest: str
    fencing_token: str
    phase: str
    evidence_revision: int
    state: LeaseState

    def __post_init__(self) -> None:
        self._redact_text_fields(
            "ticket_id", "capability_binding_digest", "fencing_token", "phase"
        )


class RuntimeAccountAllocator:
    __slots__ = (
        "_active_by_account",
        "_latest_by_account",
        "_lock",
        "_provider_adapter",
        "_records",
    )

    def __init__(self, provider_adapter: CapabilityProviderAdapter) -> None:
        self._provider_adapter = provider_adapter
        self._active_by_account: dict[str, dict[str, tuple[int, int]]] = {}
        self._latest_by_account: dict[str, tuple[int, int]] = {}
        self._lock = Lock()
        self._records: dict[str, _LeaseRecord] = {}

    def allocate(self, ticket: object, capacity_evidence: object) -> CredentialLease:
        if not self._ticket_is_valid(ticket) or not self._evidence_is_valid(
            ticket, capacity_evidence
        ):
            raise AllocationDenied("runtime account allocation denied")

        try:
            adapter_id = self._provider_adapter.adapter_id
        except Exception:
            raise AllocationDenied("runtime account allocation denied") from None
        if (
            type(adapter_id) is not str
            or not adapter_id
            or adapter_id != capacity_evidence.provider_adapter_id
        ):
            raise AllocationDenied("runtime account allocation denied")

        try:
            reservation = self._provider_adapter.reserve_capability_atomically(
                ticket.capability_binding_digest,
                capacity_evidence,
            )
        except Exception:
            raise AllocationDenied("runtime account allocation denied") from None
        if not self._reservation_matches_evidence(reservation, capacity_evidence):
            if type(reservation) is AccountReservation:
                self._release_reservation(reservation)
            raise AllocationDenied("runtime account allocation denied") from None

        rejected = False
        with self._lock:
            active = self._active_by_account.get(reservation.account_binding_digest, {})
            latest = self._latest_by_account.get(reservation.account_binding_digest)
            if (
                latest is not None
                and (
                    capacity_evidence.evidence_revision <= latest[0]
                    or reservation.lease_revision <= latest[1]
                )
            ) or (
                active
                and min(
                    capacity_evidence.capacity_units,
                    capacity_evidence.quota_units,
                    capacity_evidence.cost_units,
                    capacity_evidence.resource_units,
                )
                <= len(active)
            ):
                rejected = True
            else:
                lease = CredentialLease(
                    lease_id=token_urlsafe(18),
                    account_binding_digest=reservation.account_binding_digest,
                    profile_binding_digest=reservation.profile_binding_digest,
                    provider_adapter_id=adapter_id,
                    lease_revision=reservation.lease_revision,
                    expires_at_utc=reservation.expires_at_utc,
                )
                self._records[lease.lease_id] = _LeaseRecord(
                    lease=lease,
                    reservation=reservation,
                    ticket_id=ticket.ticket_id,
                    ledger_revision=ticket.ledger_revision,
                    capability_binding_digest=ticket.capability_binding_digest,
                    fencing_token=ticket.fencing_token,
                    phase="LEASE_RESERVED",
                    evidence_revision=capacity_evidence.evidence_revision,
                    state=LeaseState.RESERVED,
                )
                self._active_by_account.setdefault(
                    reservation.account_binding_digest, {}
                )[lease.lease_id] = (
                    capacity_evidence.evidence_revision,
                    reservation.lease_revision,
                )
                self._latest_by_account[reservation.account_binding_digest] = (
                    capacity_evidence.evidence_revision,
                    reservation.lease_revision,
                )

        if rejected:
            self._release_reservation(reservation)
            raise AllocationDenied("runtime account allocation denied") from None
        return lease

    def revoke(self, lease: object, reason: object) -> None:
        del reason
        if type(lease) is not CredentialLease:
            return
        reservation = None
        with self._lock:
            record = self._records.get(lease.lease_id)
            if record is None or record.lease is not lease:
                return
            if record.state is LeaseState.REVOKED:
                return
            self._records[lease.lease_id] = replace(record, state=LeaseState.REVOKED)
            active = self._active_by_account.get(lease.account_binding_digest)
            if active is not None:
                active.pop(lease.lease_id, None)
            reservation = record.reservation
        self._release_reservation(reservation)

    def recover(self, lease: object, transaction_evidence: object) -> LeaseState:
        if not (
            type(lease) is CredentialLease
            and self._transaction_evidence_is_valid(transaction_evidence)
        ):
            raise AllocationDenied("runtime account allocation denied")
        with self._lock:
            record = self._records.get(transaction_evidence.lease_id)
            if (
                record is None
                or record.lease is not lease
                or record.state is not LeaseState.RESERVED
                or (
                    transaction_evidence.ticket_id != record.ticket_id
                    or transaction_evidence.lease_id != lease.lease_id
                    or transaction_evidence.lease_revision
                    != record.lease.lease_revision
                    or transaction_evidence.ledger_revision != record.ledger_revision
                    or transaction_evidence.capability_binding_digest
                    != record.capability_binding_digest
                    or transaction_evidence.account_binding_digest
                    != lease.account_binding_digest
                    or transaction_evidence.profile_binding_digest
                    != lease.profile_binding_digest
                    or transaction_evidence.provider_adapter_id
                    != lease.provider_adapter_id
                    or transaction_evidence.fencing_token != record.fencing_token
                    or transaction_evidence.phase != record.phase
                    or transaction_evidence.phase != "LEASE_RESERVED"
                )
            ):
                raise AllocationDenied("runtime account allocation denied")
            return record.state

    @staticmethod
    def _ticket_is_valid(ticket: object) -> bool:
        if type(ticket) is not ValidatedAllocationTicket:
            return False
        return (
            type(ticket.resolution_decision) is ResolutionDecision
            and ticket.phase == "OFFER_VALIDATED"
            and all(
                type(value) is int and value > 0
                for value in (
                    ticket.resolver_offer_generation,
                    ticket.policy_generation,
                    ticket.ledger_revision,
                )
            )
            and all(
                type(value) is _OpaqueText and bool(value)
                for value in (
                    ticket.ticket_id,
                    ticket.capability_binding_digest,
                    ticket.fencing_token,
                )
            )
        )

    @staticmethod
    def _evidence_is_valid(
        ticket: ValidatedAllocationTicket, capacity_evidence: object
    ) -> bool:
        if type(capacity_evidence) is not CapacityEvidence:
            return False
        numeric_evidence = (
            capacity_evidence.resolver_offer_generation,
            capacity_evidence.policy_generation,
            capacity_evidence.ledger_revision,
            capacity_evidence.capacity_units,
            capacity_evidence.quota_units,
            capacity_evidence.cost_units,
            capacity_evidence.resource_units,
            capacity_evidence.evidence_revision,
        )
        if any(type(value) is not int or value <= 0 for value in numeric_evidence):
            return False
        if not all(
            type(value) is _OpaqueText and bool(value)
            for value in (
                capacity_evidence.ticket_id,
                capacity_evidence.capability_binding_digest,
                capacity_evidence.fencing_token,
                capacity_evidence.provider_adapter_id,
            )
        ):
            return False
        if not all(
            type(value) is datetime and value.tzinfo is not None
            for value in (
                capacity_evidence.observed_at_utc,
                capacity_evidence.expires_at_utc,
            )
        ):
            return False
        try:
            fresh = (
                capacity_evidence.observed_at_utc
                <= datetime.now(UTC)
                <= capacity_evidence.expires_at_utc
            )
        except Exception:
            return False
        return fresh and (
            capacity_evidence.ticket_id == ticket.ticket_id
            and capacity_evidence.resolver_offer_generation
            == ticket.resolver_offer_generation
            and capacity_evidence.policy_generation == ticket.policy_generation
            and capacity_evidence.capability_binding_digest
            == ticket.capability_binding_digest
            and capacity_evidence.ledger_revision == ticket.ledger_revision
            and capacity_evidence.fencing_token == ticket.fencing_token
        )

    @staticmethod
    def _transaction_evidence_is_valid(transaction_evidence: object) -> bool:
        return type(transaction_evidence) is TransactionEvidence and (
            all(
                type(value) is int and value > 0
                for value in (
                    transaction_evidence.lease_revision,
                    transaction_evidence.ledger_revision,
                )
            )
            and all(
                type(value) is _OpaqueText and bool(value)
                for value in (
                    transaction_evidence.ticket_id,
                    transaction_evidence.lease_id,
                    transaction_evidence.capability_binding_digest,
                    transaction_evidence.account_binding_digest,
                    transaction_evidence.profile_binding_digest,
                    transaction_evidence.provider_adapter_id,
                    transaction_evidence.fencing_token,
                    transaction_evidence.phase,
                )
            )
        )

    @staticmethod
    def _reservation_matches_evidence(
        reservation: object, capacity_evidence: CapacityEvidence
    ) -> bool:
        try:
            return type(reservation) is AccountReservation and (
                all(
                    type(value) is _OpaqueText and bool(value)
                    for value in (
                        reservation.reservation_id,
                        reservation.account_binding_digest,
                        reservation.profile_binding_digest,
                        reservation.provider_adapter_id,
                        reservation.fencing_token,
                    )
                )
                and type(reservation.lease_revision) is int
                and reservation.lease_revision > 0
                and type(reservation.evidence_revision) is int
                and reservation.evidence_revision > 0
                and type(reservation.expires_at_utc) is datetime
                and reservation.expires_at_utc.tzinfo is not None
                and reservation.provider_adapter_id
                == capacity_evidence.provider_adapter_id
                and reservation.evidence_revision == capacity_evidence.evidence_revision
                and reservation.fencing_token == capacity_evidence.fencing_token
                and reservation.expires_at_utc == capacity_evidence.expires_at_utc
            )
        except Exception:
            return False

    def _release_reservation(self, reservation: AccountReservation) -> None:
        try:
            self._provider_adapter.release_reservation(reservation)
        except Exception:
            return


__all__ = [
    "AccountReservation",
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
