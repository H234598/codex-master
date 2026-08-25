"""Private resolver evidence carriers for the worker registry boundary."""

from __future__ import annotations

from dataclasses import dataclass

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
    LedgerRevision,
    WorkerSpawnTicketV2,
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
        "lease_binding_digest",
        "account_binding_digest",
        "profile_binding_digest",
    )

    def __init__(
        self,
        *,
        principal_id: str,
        resolution: WorkerResolutionCarrierV2,
        ticket_ledger_revision: LedgerRevision,
        ticket_fence_epoch: FenceEpoch,
        lease_binding_digest: None,
        account_binding_digest: None,
        profile_binding_digest: None,
    ) -> None:
        object.__setattr__(self, "principal_id", principal_id)
        object.__setattr__(self, "resolution", resolution)
        object.__setattr__(self, "ticket_ledger_revision", ticket_ledger_revision)
        object.__setattr__(self, "ticket_fence_epoch", ticket_fence_epoch)
        object.__setattr__(self, "lease_binding_digest", lease_binding_digest)
        object.__setattr__(self, "account_binding_digest", account_binding_digest)
        object.__setattr__(self, "profile_binding_digest", profile_binding_digest)

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

    @property
    def lease_binding_digest(self) -> None:
        return object.__getattribute__(self, "_payload").lease_binding_digest

    @property
    def account_binding_digest(self) -> None:
        return object.__getattribute__(self, "_payload").account_binding_digest

    @property
    def profile_binding_digest(self) -> None:
        return object.__getattribute__(self, "_payload").profile_binding_digest


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


def build_worker_registry_reservation(
    *,
    resolution: object,
    principal_id: object,
    ticket_ledger_revision: object,
    ticket_fence_epoch: object,
) -> WorkerRegistryReservationV2:
    """Issue an unbound R1 reservation carrier; lease bindings arrive in a later slice."""

    if (
        type(resolution) is not WorkerResolutionCarrierV2
        or type(principal_id) is not str
        or not principal_id
        or len(principal_id) > 256
        or type(ticket_ledger_revision) is not LedgerRevision
        or ticket_ledger_revision.value < 1
        or type(ticket_fence_epoch) is not FenceEpoch
        or ticket_fence_epoch != resolution.ticket_fence_epoch
    ):
        raise WorkerResolutionCarrierDenied("invalid worker registry reservation")
    return WorkerRegistryReservationV2._issue(
        _ReservationPayload(
            principal_id=principal_id,
            resolution=resolution,
            ticket_ledger_revision=ticket_ledger_revision,
            ticket_fence_epoch=ticket_fence_epoch,
            lease_binding_digest=None,
            account_binding_digest=None,
            profile_binding_digest=None,
        )
    )
