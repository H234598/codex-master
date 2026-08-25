from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import Enum
from secrets import token_urlsafe
from threading import Lock
from typing import Protocol

from codex_master.agent_resolver import (
    ResolutionDecision,
    SelectionOffer,
    SelectionOption,
)


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
    selection_offer: SelectionOffer
    resolver_offer_generation: str
    policy_generation: int
    capability_binding_digest: str
    ledger_revision: int
    phase: str
    fencing_token: str

    def __post_init__(self) -> None:
        self._redact_text_fields(
            "ticket_id",
            "resolver_offer_generation",
            "capability_binding_digest",
            "phase",
            "fencing_token",
        )


@dataclass(frozen=True, slots=True, repr=False)
class CapacityEvidence(_RedactedNonSerializable):
    ticket_id: str
    resolver_offer_generation: str
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
            "resolver_offer_generation",
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
    capacity_evidence: CapacityEvidence
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

    def release_reservation(self, reservation: AccountReservation) -> bool: ...


class LeaseState(str, Enum):
    RESERVED = "reserved"
    RELEASE_PENDING = "release_pending"
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
    reservation_key: str
    state: LeaseState
    pending_release_id: str | None

    def __post_init__(self) -> None:
        self._redact_text_fields(
            "ticket_id",
            "capability_binding_digest",
            "fencing_token",
            "phase",
            "reservation_key",
            "pending_release_id",
        )


@dataclass(frozen=True, slots=True, repr=False)
class _PendingRelease(_RedactedNonSerializable):
    pending_release_id: str
    reservation_key: str
    reservation: AccountReservation
    active_account_key: str | None
    active_key: str | None
    fencing_token: str
    lease_id: str | None

    def __post_init__(self) -> None:
        self._redact_text_fields(
            "pending_release_id",
            "reservation_key",
            "active_account_key",
            "active_key",
            "fencing_token",
            "lease_id",
        )


@dataclass(frozen=True, slots=True, repr=False)
class _ReservationOwner(_RedactedNonSerializable):
    reservation_key: str
    owner_id: str
    reservation: AccountReservation
    fencing_token: str
    phase: LeaseState
    lease_id: str | None

    def __post_init__(self) -> None:
        self._redact_text_fields(
            "reservation_key",
            "owner_id",
            "fencing_token",
            "lease_id",
        )


class RuntimeAccountAllocator:
    __slots__ = (
        "_active_by_account",
        "_latest_by_account",
        "_lock",
        "_pending_releases",
        "_provider_adapter",
        "_records",
        "_release_lock",
        "_reservation_owners",
    )

    def __init__(self, provider_adapter: CapabilityProviderAdapter) -> None:
        self._provider_adapter = provider_adapter
        self._active_by_account: dict[str, dict[str, tuple[int, int]]] = {}
        self._latest_by_account: dict[str, tuple[int, int]] = {}
        self._lock = Lock()
        self._pending_releases: dict[str, _PendingRelease] = {}
        self._records: dict[str, _LeaseRecord] = {}
        self._release_lock = Lock()
        self._reservation_owners: dict[str, _ReservationOwner] = {}

    def allocate(self, ticket: object, capacity_evidence: object) -> CredentialLease:
        if not self._allocation_binding_invariant(ticket, capacity_evidence):
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

        with self._lock:
            lease, pending_release_id = self._bind_reservation_locked(
                ticket,
                capacity_evidence,
                adapter_id,
                reservation,
            )

        if pending_release_id is not None:
            self._retry_pending_release(pending_release_id)
        if lease is None:
            raise AllocationDenied("runtime account allocation denied") from None
        return lease

    def revoke(self, lease: object, reason: object) -> None:
        del reason
        if type(lease) is not CredentialLease:
            return
        pending_release_id = None
        with self._lock:
            record = self._records.get(lease.lease_id)
            if record is None or record.lease is not lease:
                return
            if record.state is LeaseState.REVOKED:
                return
            if record.state is LeaseState.RESERVED:
                pending_release_id = self._transition_lease_release_locked(record)
            elif record.state is LeaseState.RELEASE_PENDING:
                pending_release_id = record.pending_release_id
        if pending_release_id is not None:
            self._retry_pending_release(pending_release_id)

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
                )
            ):
                raise AllocationDenied("runtime account allocation denied")
            if record.state is LeaseState.RESERVED:
                if transaction_evidence.phase != "LEASE_RESERVED":
                    raise AllocationDenied("runtime account allocation denied")
                return record.state
            if (
                record.state is not LeaseState.RELEASE_PENDING
                or transaction_evidence.phase != "RELEASE_PENDING"
                or record.pending_release_id is None
            ):
                raise AllocationDenied("runtime account allocation denied")
            pending_release_id = record.pending_release_id

        self._retry_pending_release(pending_release_id)
        with self._lock:
            record = self._records.get(lease.lease_id)
            if record is None or record.lease is not lease:
                raise AllocationDenied("runtime account allocation denied")
            return record.state

    def recover_pending_releases(self) -> int:
        with self._lock:
            pending_release_ids = tuple(self._pending_releases)
        for pending_release_id in pending_release_ids:
            self._retry_pending_release(pending_release_id)
        with self._lock:
            return len(self._pending_releases)

    @staticmethod
    def _allocation_binding_invariant(
        ticket: object, capacity_evidence: object
    ) -> bool:
        if (
            type(ticket) is not ValidatedAllocationTicket
            or type(capacity_evidence) is not CapacityEvidence
            or not RuntimeAccountAllocator._central_resolution_offer_invariant(ticket)
            or ticket.phase != "OFFER_VALIDATED"
        ):
            return False
        if any(
            type(value) is not int or value <= 0
            for value in (
                ticket.policy_generation,
                ticket.ledger_revision,
                capacity_evidence.policy_generation,
                capacity_evidence.ledger_revision,
                capacity_evidence.capacity_units,
                capacity_evidence.quota_units,
                capacity_evidence.cost_units,
                capacity_evidence.resource_units,
                capacity_evidence.evidence_revision,
            )
        ):
            return False
        if not all(
            type(value) is _OpaqueText and bool(value)
            for value in (
                ticket.ticket_id,
                ticket.resolver_offer_generation,
                ticket.capability_binding_digest,
                ticket.phase,
                ticket.fencing_token,
                capacity_evidence.ticket_id,
                capacity_evidence.resolver_offer_generation,
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
            capacity_evidence.ticket_id,
            capacity_evidence.resolver_offer_generation,
            capacity_evidence.policy_generation,
            capacity_evidence.capability_binding_digest,
            capacity_evidence.ledger_revision,
            capacity_evidence.fencing_token,
        ) == (
            ticket.ticket_id,
            ticket.resolver_offer_generation,
            ticket.policy_generation,
            ticket.capability_binding_digest,
            ticket.ledger_revision,
            ticket.fencing_token,
        )

    @staticmethod
    def _central_resolution_offer_invariant(
        ticket: ValidatedAllocationTicket,
    ) -> bool:
        decision = ticket.resolution_decision
        offer = ticket.selection_offer
        if (
            type(decision) is not ResolutionDecision
            or type(offer) is not SelectionOffer
        ):
            return False
        decision_fields = (
            decision.class_id,
            decision.lifecycle,
            decision.model,
            decision.reasoning,
        )
        if not all(type(value) is str and bool(value) for value in decision_fields):
            return False
        if (
            type(decision.reason_codes) is not tuple
            or any(
                type(value) is not str or not value for value in decision.reason_codes
            )
            or type(decision.fallback) is not bool
            or any(
                value is not None and (type(value) is not str or not value)
                for value in (
                    decision.requested_class,
                    decision.requested_lifecycle,
                    decision.requested_model,
                    decision.requested_reasoning,
                )
            )
        ):
            return False
        if type(offer.options) is not tuple or any(
            type(option) is not SelectionOption
            or any(
                type(value) is not str or not value
                for value in (
                    option.class_id,
                    option.lifecycle,
                    option.model,
                    option.reasoning,
                )
            )
            for option in offer.options
        ):
            return False
        option_rows = tuple(
            (option.class_id, option.lifecycle, option.model, option.reasoning)
            for option in offer.options
        )
        canonical_generation = (
            "sha256:"
            + hashlib.sha256(
                json.dumps(
                    list(option_rows),
                    ensure_ascii=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
        )
        derived_offer = (
            tuple(dict.fromkeys(row[0] for row in option_rows)),
            tuple(dict.fromkeys(row[1] for row in option_rows)),
            tuple(dict.fromkeys(row[2] for row in option_rows)),
            tuple(dict.fromkeys(row[3] for row in option_rows)),
        )
        return (
            type(offer.generation) is str
            and offer.generation == canonical_generation
            and ticket.resolver_offer_generation == canonical_generation
            and (
                offer.classes,
                offer.lifecycles,
                offer.models,
                offer.reasoning_levels,
            )
            == derived_offer
            and decision_fields in option_rows
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

    def _bind_reservation_locked(
        self,
        ticket: ValidatedAllocationTicket,
        capacity_evidence: CapacityEvidence,
        adapter_id: str,
        reservation: object,
    ) -> tuple[CredentialLease | None, str | None]:
        if type(reservation) is not AccountReservation:
            return None, None
        reservation_key = self._reservation_key(reservation)
        if reservation_key in self._reservation_owners:
            return None, None
        if not (
            self._allocation_binding_invariant(ticket, capacity_evidence)
            and adapter_id == capacity_evidence.provider_adapter_id
            and self._reservation_matches_evidence(
                reservation,
                capacity_evidence,
            )
        ):
            return None, self._queue_new_pending_release_locked(
                reservation,
                reservation_key,
                ticket.fencing_token,
            )

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
            return None, self._queue_new_pending_release_locked(
                reservation,
                reservation_key,
                ticket.fencing_token,
            )

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
            reservation_key=reservation_key,
            state=LeaseState.RESERVED,
            pending_release_id=None,
        )
        self._reservation_owners[reservation_key] = _ReservationOwner(
            reservation_key=reservation_key,
            owner_id=lease.lease_id,
            reservation=reservation,
            fencing_token=ticket.fencing_token,
            phase=LeaseState.RESERVED,
            lease_id=lease.lease_id,
        )
        self._active_by_account.setdefault(reservation.account_binding_digest, {})[
            lease.lease_id
        ] = (
            capacity_evidence.evidence_revision,
            reservation.lease_revision,
        )
        self._latest_by_account[reservation.account_binding_digest] = (
            capacity_evidence.evidence_revision,
            reservation.lease_revision,
        )
        return lease, None

    @staticmethod
    def _reservation_key(reservation: AccountReservation) -> str:
        reservation_id = reservation.reservation_id
        if type(reservation_id) is _OpaqueText and reservation_id:
            key_material = reservation_id.encode("utf-8")
        else:
            key_material = f"reply-object:{id(reservation)}".encode("ascii")
        return _OpaqueText("sha256:" + hashlib.sha256(key_material).hexdigest())

    @staticmethod
    def _reservation_matches_evidence(
        reservation: object, capacity_evidence: CapacityEvidence
    ) -> bool:
        try:
            return RuntimeAccountAllocator._reservation_is_well_formed(
                reservation
            ) and (
                reservation.capacity_evidence is capacity_evidence
                and reservation.provider_adapter_id
                == capacity_evidence.provider_adapter_id
                and reservation.evidence_revision == capacity_evidence.evidence_revision
                and reservation.fencing_token == capacity_evidence.fencing_token
                and reservation.expires_at_utc == capacity_evidence.expires_at_utc
            )
        except Exception:
            return False

    @staticmethod
    def _reservation_is_well_formed(reservation: object) -> bool:
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
            and type(reservation.capacity_evidence) is CapacityEvidence
            and type(reservation.lease_revision) is int
            and reservation.lease_revision > 0
            and type(reservation.evidence_revision) is int
            and reservation.evidence_revision > 0
            and type(reservation.expires_at_utc) is datetime
            and reservation.expires_at_utc.tzinfo is not None
        )

    def _queue_new_pending_release_locked(
        self,
        reservation: AccountReservation,
        reservation_key: str,
        fencing_token: str,
    ) -> str:
        pending_release_id = token_urlsafe(18)
        well_formed = self._reservation_is_well_formed(reservation)
        active_account_key = reservation.account_binding_digest if well_formed else None
        active_key = pending_release_id if well_formed else None
        pending = _PendingRelease(
            pending_release_id=pending_release_id,
            reservation_key=reservation_key,
            reservation=reservation,
            active_account_key=active_account_key,
            active_key=active_key,
            fencing_token=fencing_token,
            lease_id=None,
        )
        self._pending_releases[pending.pending_release_id] = pending
        self._reservation_owners[reservation_key] = _ReservationOwner(
            reservation_key=reservation_key,
            owner_id=pending_release_id,
            reservation=reservation,
            fencing_token=fencing_token,
            phase=LeaseState.RELEASE_PENDING,
            lease_id=None,
        )
        if active_account_key is not None and active_key is not None:
            self._active_by_account.setdefault(active_account_key, {})[active_key] = (
                reservation.evidence_revision,
                reservation.lease_revision,
            )
        return pending.pending_release_id

    def _transition_lease_release_locked(self, record: _LeaseRecord) -> str | None:
        owner = self._reservation_owners.get(record.reservation_key)
        if not self._reservation_owner_invariant(
            owner,
            reservation_key=record.reservation_key,
            owner_id=record.lease.lease_id,
            reservation=record.reservation,
            fencing_token=record.fencing_token,
            phase=LeaseState.RESERVED,
            lease_id=record.lease.lease_id,
        ):
            return None
        pending_release_id = token_urlsafe(18)
        pending = _PendingRelease(
            pending_release_id=pending_release_id,
            reservation_key=record.reservation_key,
            reservation=record.reservation,
            active_account_key=record.lease.account_binding_digest,
            active_key=record.lease.lease_id,
            fencing_token=record.fencing_token,
            lease_id=record.lease.lease_id,
        )
        self._pending_releases[pending_release_id] = pending
        self._reservation_owners[record.reservation_key] = replace(
            owner,
            owner_id=pending_release_id,
            phase=LeaseState.RELEASE_PENDING,
        )
        self._records[record.lease.lease_id] = replace(
            record,
            state=LeaseState.RELEASE_PENDING,
            phase="RELEASE_PENDING",
            pending_release_id=pending_release_id,
        )
        return pending_release_id

    def _retry_pending_release(self, pending_release_id: str) -> bool:
        with self._release_lock:
            with self._lock:
                pending = self._pending_releases.get(pending_release_id)
                owner = (
                    None
                    if pending is None
                    else self._reservation_owners.get(pending.reservation_key)
                )
            if pending is None:
                return True
            if not self._reservation_owner_invariant(
                owner,
                reservation_key=pending.reservation_key,
                owner_id=pending.pending_release_id,
                reservation=pending.reservation,
                fencing_token=pending.fencing_token,
                phase=LeaseState.RELEASE_PENDING,
                lease_id=pending.lease_id,
            ):
                return False
            if not self._release_reservation(pending.reservation):
                return False
            with self._lock:
                owner = self._reservation_owners.get(pending.reservation_key)
                if self._pending_releases.get(
                    pending_release_id
                ) is not pending or not self._reservation_owner_invariant(
                    owner,
                    reservation_key=pending.reservation_key,
                    owner_id=pending.pending_release_id,
                    reservation=pending.reservation,
                    fencing_token=pending.fencing_token,
                    phase=LeaseState.RELEASE_PENDING,
                    lease_id=pending.lease_id,
                ):
                    return False
                self._pending_releases.pop(pending_release_id)
                self._reservation_owners.pop(pending.reservation_key)
                if (
                    pending.active_account_key is not None
                    and pending.active_key is not None
                ):
                    active = self._active_by_account.get(pending.active_account_key)
                else:
                    active = None
                if active is not None and pending.active_key is not None:
                    active.pop(pending.active_key, None)
                if pending.lease_id is not None:
                    record = self._records.get(pending.lease_id)
                    if (
                        record is not None
                        and record.reservation is pending.reservation
                        and record.reservation_key == pending.reservation_key
                        and record.pending_release_id == pending_release_id
                    ):
                        self._records[pending.lease_id] = replace(
                            record,
                            state=LeaseState.REVOKED,
                            phase="LEASE_REVOKED",
                            pending_release_id=None,
                        )
            return True

    @staticmethod
    def _reservation_owner_invariant(
        owner: _ReservationOwner | None,
        *,
        reservation_key: str,
        owner_id: str,
        reservation: AccountReservation,
        fencing_token: str,
        phase: LeaseState,
        lease_id: str | None,
    ) -> bool:
        return (
            owner is not None
            and owner.reservation_key == reservation_key
            and owner.owner_id == owner_id
            and owner.reservation is reservation
            and owner.fencing_token == fencing_token
            and owner.phase is phase
            and owner.lease_id == lease_id
        )

    def _release_reservation(self, reservation: AccountReservation) -> bool:
        try:
            released = self._provider_adapter.release_reservation(reservation)
        except Exception:
            return False
        return type(released) is bool and released


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
