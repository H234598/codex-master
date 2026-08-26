"""Private resolver evidence carriers for the worker registry boundary."""

from __future__ import annotations

from dataclasses import dataclass
import re

from codex_master.agent_resolver import (
    LEADERSHIP_CLASS_IDS,
    ResolutionDecision,
    SelectionOffer,
    canonical_resolution_decision_digest,
    canonical_worker_lifecycle,
    validate_resolution_decision_offer,
)
from codex_master.worker_spawn_ledger import (
    FenceEpoch,
    Generation,
    LeaseBindingConsumerInputV1,
    LedgerRevision,
    SpawnPhase,
    WorkerSpawnTicketV2,
)
from codex_master.runtime_account_allocator import (
    AllocationDenied,
    LeaseBindingReferenceV1,
    RuntimeAccountAllocator,
    ValidatedAllocationTicket,
)


class WorkerResolutionCarrierDenied(ValueError):
    """Raised when worker resolver evidence is incomplete or has drifted."""


class _RedactedNonSerializable:
    __slots__ = ()

    def __repr__(self) -> str:
        return f"<{type(self).__name__} redacted>"

    __str__ = __repr__

    def __reduce_ex__(self, _protocol: int) -> object:
        raise TypeError("worker resolution carriers are not serializable")

    def __copy__(self) -> object:
        raise TypeError("worker resolution carriers are not serializable")

    def __deepcopy__(self, _memo: object) -> object:
        raise TypeError("worker resolution carriers are not serializable")


class _ResolutionPayload:
    __slots__ = (
        "ticket_id",
        "ticket_fence_epoch",
        "ticket_resolution_generation",
        "ticket_policy_digest",
        "ticket_policy_generation",
        "capability_binding_digest",
        "resolution_decision_digest",
        "decision",
        "offer",
        "resolver_offer_generation",
    )

    def __init__(
        self,
        *,
        ticket_id: str,
        ticket_fence_epoch: FenceEpoch,
        ticket_resolution_generation: Generation,
        ticket_policy_digest: str,
        ticket_policy_generation: Generation,
        capability_binding_digest: str,
        resolution_decision_digest: str,
        decision: ResolutionDecision,
        offer: SelectionOffer,
        resolver_offer_generation: str,
    ) -> None:
        object.__setattr__(self, "ticket_id", ticket_id)
        object.__setattr__(self, "ticket_fence_epoch", ticket_fence_epoch)
        object.__setattr__(
            self, "ticket_resolution_generation", ticket_resolution_generation
        )
        object.__setattr__(self, "ticket_policy_digest", ticket_policy_digest)
        object.__setattr__(self, "ticket_policy_generation", ticket_policy_generation)
        object.__setattr__(self, "capability_binding_digest", capability_binding_digest)
        object.__setattr__(
            self, "resolution_decision_digest", resolution_decision_digest
        )
        object.__setattr__(self, "decision", decision)
        object.__setattr__(self, "offer", offer)
        object.__setattr__(self, "resolver_offer_generation", resolver_offer_generation)

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("worker resolution payload is immutable")

    def __deepcopy__(self, _memo: object) -> object:
        raise TypeError("worker resolution carriers are not serializable")


class _ReservationPayload:
    __slots__ = (
        "principal_id",
        "resolution",
        "ticket_ledger_revision",
        "ticket_fence_epoch",
        "binding_input",
        "binding_reference",
    )

    def __init__(
        self,
        *,
        principal_id: str,
        resolution: WorkerResolutionCarrierV2,
        ticket_ledger_revision: LedgerRevision,
        ticket_fence_epoch: FenceEpoch,
        binding_input: LeaseBindingConsumerInputV1,
        binding_reference: LeaseBindingReferenceV1,
    ) -> None:
        object.__setattr__(self, "principal_id", principal_id)
        object.__setattr__(self, "resolution", resolution)
        object.__setattr__(self, "ticket_ledger_revision", ticket_ledger_revision)
        object.__setattr__(self, "ticket_fence_epoch", ticket_fence_epoch)
        object.__setattr__(self, "binding_input", binding_input)
        object.__setattr__(self, "binding_reference", binding_reference)

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("worker registry reservation payload is immutable")

    def __deepcopy__(self, _memo: object) -> object:
        raise TypeError("worker resolution carriers are not serializable")


@dataclass(frozen=True, slots=True)
class WorkerResolutionEvidenceV2:
    """Narrow resolver-port value injected after central resolution."""

    decision: ResolutionDecision
    offer: SelectionOffer
    offer_generation: str
    capability_binding_digest: str
    resolution_generation: Generation
    policy_digest: str
    policy_generation: Generation
    ticket_fence_epoch: FenceEpoch


@dataclass(frozen=True, slots=True, repr=False, init=False, eq=False)
class WorkerResolutionCarrierV2(_RedactedNonSerializable):
    _payload: _ResolutionPayload

    @classmethod
    def _issue(cls, payload: _ResolutionPayload) -> WorkerResolutionCarrierV2:
        issued = object.__new__(cls)
        object.__setattr__(issued, "_payload", payload)
        return issued

    def __getattribute__(self, name: str) -> object:
        if name == "_payload":
            raise TypeError("worker resolution carriers are not serializable")
        return super().__getattribute__(name)

    @property
    def ticket_id(self) -> str:
        return object.__getattribute__(self, "_payload").ticket_id

    @property
    def ticket_fence_epoch(self) -> FenceEpoch:
        return object.__getattribute__(self, "_payload").ticket_fence_epoch

    @property
    def ticket_resolution_generation(self) -> Generation:
        return object.__getattribute__(self, "_payload").ticket_resolution_generation

    @property
    def ticket_policy_digest(self) -> str:
        return object.__getattribute__(self, "_payload").ticket_policy_digest

    @property
    def ticket_policy_generation(self) -> Generation:
        return object.__getattribute__(self, "_payload").ticket_policy_generation

    @property
    def capability_binding_digest(self) -> str:
        return object.__getattribute__(self, "_payload").capability_binding_digest

    @property
    def resolution_decision_digest(self) -> str:
        return object.__getattribute__(self, "_payload").resolution_decision_digest

    @property
    def decision(self) -> ResolutionDecision:
        return object.__getattribute__(self, "_payload").decision

    @property
    def offer(self) -> SelectionOffer:
        return object.__getattribute__(self, "_payload").offer

    @property
    def resolver_offer_generation(self) -> str:
        return object.__getattribute__(self, "_payload").resolver_offer_generation


@dataclass(frozen=True, slots=True, repr=False, init=False, eq=False)
class WorkerRegistryReservationV2(_RedactedNonSerializable):
    _payload: _ReservationPayload

    @classmethod
    def _issue(cls, payload: _ReservationPayload) -> WorkerRegistryReservationV2:
        issued = object.__new__(cls)
        object.__setattr__(issued, "_payload", payload)
        return issued

    def __getattribute__(self, name: str) -> object:
        if name == "_payload":
            raise TypeError("worker resolution carriers are not serializable")
        return super().__getattribute__(name)

    @property
    def principal_id(self) -> str:
        return object.__getattribute__(self, "_payload").principal_id

    @property
    def resolution(self) -> WorkerResolutionCarrierV2:
        return object.__getattribute__(self, "_payload").resolution

    @property
    def ticket_ledger_revision(self) -> LedgerRevision:
        return object.__getattribute__(self, "_payload").ticket_ledger_revision

    @property
    def ticket_fence_epoch(self) -> FenceEpoch:
        return object.__getattribute__(self, "_payload").ticket_fence_epoch

    def _binding_input(self) -> LeaseBindingConsumerInputV1:
        return object.__getattribute__(self, "_payload").binding_input

    def _binding_reference(self) -> LeaseBindingReferenceV1:
        return object.__getattribute__(self, "_payload").binding_reference


def build_worker_resolution_carrier(
    ticket: object,
    central_evidence: object,
) -> WorkerResolutionCarrierV2:
    """Bind a digest-only B5-2 ticket to complete central resolver evidence."""

    if (
        type(ticket) is not WorkerSpawnTicketV2
        or type(central_evidence) is not WorkerResolutionEvidenceV2
    ):
        raise WorkerResolutionCarrierDenied(
            "nominal ticket and resolver evidence required"
        )
    try:
        validate_resolution_decision_offer(
            central_evidence.decision, central_evidence.offer
        )
        decision_digest = canonical_resolution_decision_digest(
            central_evidence.decision
        )
        ticket_lifecycle = canonical_worker_lifecycle(ticket.lifecycle.value)
        decision_lifecycle = canonical_worker_lifecycle(
            central_evidence.decision.lifecycle
        )
    except ValueError as exc:
        raise WorkerResolutionCarrierDenied(
            "invalid central resolution evidence"
        ) from exc
    if (
        type(central_evidence.offer_generation) is not str
        or central_evidence.offer_generation != central_evidence.offer.generation
        or type(central_evidence.capability_binding_digest) is not str
        or len(central_evidence.capability_binding_digest) != 71
        or not central_evidence.capability_binding_digest.startswith("sha256:")
        or any(
            character not in "0123456789abcdef"
            for character in central_evidence.capability_binding_digest[7:]
        )
        or type(central_evidence.resolution_generation) is not Generation
        or type(central_evidence.policy_digest) is not str
        or len(central_evidence.policy_digest) != 71
        or not central_evidence.policy_digest.startswith("sha256:")
        or any(
            character not in "0123456789abcdef"
            for character in central_evidence.policy_digest[7:]
        )
        or type(central_evidence.policy_generation) is not Generation
        or type(central_evidence.ticket_fence_epoch) is not FenceEpoch
    ):
        raise WorkerResolutionCarrierDenied("invalid central resolver evidence binding")
    if (
        decision_digest != ticket.resolution_decision_digest
        or central_evidence.resolution_generation != ticket.resolution_generation
        or central_evidence.policy_digest != ticket.policy_digest
        or central_evidence.policy_generation != ticket.policy_generation
        or central_evidence.ticket_fence_epoch != ticket.fence_epoch
        or ticket.target_class_id != central_evidence.decision.class_id
        or ticket_lifecycle != decision_lifecycle
        or central_evidence.decision.class_id in LEADERSHIP_CLASS_IDS
    ):
        raise WorkerResolutionCarrierDenied("worker resolution evidence drift")
    return WorkerResolutionCarrierV2._issue(
        _ResolutionPayload(
            ticket_id=ticket.ticket_id,
            ticket_fence_epoch=ticket.fence_epoch,
            ticket_resolution_generation=ticket.resolution_generation,
            ticket_policy_digest=ticket.policy_digest,
            ticket_policy_generation=ticket.policy_generation,
            capability_binding_digest=central_evidence.capability_binding_digest,
            resolution_decision_digest=decision_digest,
            decision=central_evidence.decision,
            offer=central_evidence.offer,
            resolver_offer_generation=central_evidence.offer_generation,
        )
    )


_DYNAMIC_WORKER_PRINCIPAL_ID_RE = re.compile(r"dw-[0-9a-f]{32}\Z")


class WorkerRegistryReservationIssuerV2:
    """Allocator-bound issuer for one exact LEASE_RESERVED ticket."""

    __slots__ = ("_allocator",)

    def __init__(self, allocator: RuntimeAccountAllocator) -> None:
        if type(allocator) is not RuntimeAccountAllocator:
            raise WorkerResolutionCarrierDenied("runtime account allocator required")
        self._allocator = allocator

    def issue(
        self,
        *,
        resolution: object,
        current_ticket: object,
        principal_id: object,
        lease_binding: object,
    ) -> WorkerRegistryReservationV2:
        if (
            type(resolution) is not WorkerResolutionCarrierV2
            or type(current_ticket) is not WorkerSpawnTicketV2
            or current_ticket.phase is not SpawnPhase.LEASE_RESERVED
            or type(principal_id) is not str
            or _DYNAMIC_WORKER_PRINCIPAL_ID_RE.fullmatch(principal_id) is None
            or type(lease_binding) is not LeaseBindingConsumerInputV1
        ):
            raise WorkerResolutionCarrierDenied("lease binding verification denied")
        allocation_ticket = lease_binding.allocation_ticket
        if (
            type(allocation_ticket) is not ValidatedAllocationTicket
            or allocation_ticket.phase != "OFFER_VALIDATED"
            or allocation_ticket.ticket_id != current_ticket.ticket_id
            or allocation_ticket.ledger_revision + 1
            != current_ticket.ledger_revision.value
            or allocation_ticket.fence_epoch != current_ticket.fence_epoch.value
            or allocation_ticket.resolution_decision is not resolution.decision
            or allocation_ticket.selection_offer is not resolution.offer
            or allocation_ticket.resolver_offer_generation
            != resolution.resolver_offer_generation
            or allocation_ticket.policy_generation
            != current_ticket.policy_generation.value
            or allocation_ticket.policy_digest != current_ticket.policy_digest
            or allocation_ticket.capability_binding_digest
            != resolution.capability_binding_digest
            or current_ticket.resolution_generation
            != resolution.ticket_resolution_generation
            or current_ticket.resolution_decision_digest
            != resolution.resolution_decision_digest
            or current_ticket.target_class_id != resolution.decision.class_id
            or current_ticket.lease_binding_reference is None
            or current_ticket.account_binding_digest
            != str(lease_binding.lease.account_binding_digest)
        ):
            raise WorkerResolutionCarrierDenied("lease binding verification denied")

        verification = None
        primary: BaseException | None = None
        try:
            try:
                verification = self._allocator.verify_lease_binding_receipt(
                    lease_binding.receipt,
                    expected_lease=lease_binding.lease,
                    expected_ticket=allocation_ticket,
                    expected_capacity_evidence=lease_binding.capacity_evidence,
                )
                reference = self._allocator.lease_binding_reference_for(verification)
            except AllocationDenied as exc:
                raise WorkerResolutionCarrierDenied(
                    "lease binding verification denied"
                ) from exc
            if (
                type(reference) is not LeaseBindingReferenceV1
                or reference != current_ticket.lease_binding_reference
            ):
                raise WorkerResolutionCarrierDenied("lease binding verification denied")
            return WorkerRegistryReservationV2._issue(
                _ReservationPayload(
                    principal_id=principal_id,
                    resolution=resolution,
                    ticket_ledger_revision=current_ticket.ledger_revision,
                    ticket_fence_epoch=current_ticket.fence_epoch,
                    binding_input=lease_binding,
                    binding_reference=reference,
                )
            )
        except BaseException as exc:
            primary = exc
            raise
        finally:
            if verification is not None:
                try:
                    self._allocator.close_lease_binding_verification(verification)
                except AllocationDenied as close_error:
                    if primary is None:
                        raise WorkerResolutionCarrierDenied(
                            "lease binding verification denied"
                        ) from close_error
                    primary.add_note(
                        "lease binding guard close denied; quarantine required"
                    )


__all__ = [
    "WorkerRegistryReservationIssuerV2",
    "WorkerRegistryReservationV2",
    "WorkerResolutionCarrierDenied",
    "WorkerResolutionCarrierV2",
    "WorkerResolutionEvidenceV2",
    "build_worker_resolution_carrier",
]
