"""Nominal worker-spawn state machine over an injected atomic CAS port."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, replace
from enum import Enum
from typing import Final

from codex_master.agent_resolver import canonical_resolution_decision_digest
from codex_master.runtime_account_allocator import (
    AllocationDenied,
    CapacityEvidence,
    CredentialLease,
    LeaseBindingReceiptV1,
    LeaseBindingReferenceV1,
    RuntimeAccountAllocator,
    ValidatedAllocationTicket,
)
from codex_master.worker_resume import (
    CapsuleGeneration,
    ResumeDenied,
    ResumeRequestPhase,
    ResumeTransactionPort,
    WorkerLifecycle,
    WorkerResumeCapsuleV2,
    WorkerResumeRequestV2,
    require_terminal_capsule,
)

_DIGEST_RE: Final = re.compile(r"^sha256:[0-9a-f]{64}$")


class SpawnDenied(ValueError):
    """Raised when a spawn-ledger operation fails closed."""


class _RedactedNonSerializable:
    __slots__ = ()

    def __repr__(self) -> str:
        return f"<{type(self).__name__} redacted>"

    __str__ = __repr__

    def __reduce_ex__(self, _protocol: int) -> object:
        raise TypeError("worker spawn ledger internals are not serializable")


def _require_text(value: object, field: str) -> str:
    if type(value) is not str or not value:
        raise SpawnDenied(f"invalid {field}")
    return value


def _require_digest(value: object, field: str) -> str:
    value = _require_text(value, field)
    if _DIGEST_RE.fullmatch(value) is None:
        raise SpawnDenied(f"invalid {field}")
    return value


def _require_counter(value: object, field: str) -> int:
    if type(value) is not int or value < 0:
        raise SpawnDenied(f"invalid {field}")
    return value


class PrincipalRole(str, Enum):
    NON_LEADERSHIP = "non_leadership"
    TEAMLEADER = "teamleader"
    QUEEN = "queen"


class WorkerFailureCodeV1(str, Enum):
    PRE_A3_FAILURE = "PRE_A3_FAILURE"
    A3_EXECUTION_FAILED_OR_UNKNOWN = "A3_EXECUTION_FAILED_OR_UNKNOWN"
    START_STATE_UNKNOWN = "START_STATE_UNKNOWN"


class WorkerFailureOriginV1(str, Enum):
    PRE_A3 = "PRE_A3"
    A3_ENTERED = "A3_ENTERED"
    RECOVERY_UNKNOWN = "RECOVERY_UNKNOWN"


class CompensationStatusV1(str, Enum):
    NONE = "NONE"
    REGISTRY_RELEASE_PENDING = "REGISTRY_RELEASE_PENDING"
    REGISTRY_RELEASED = "REGISTRY_RELEASED"
    HOME_RELEASE_FAILED = "HOME_RELEASE_FAILED"
    LEASE_RELEASE_FAILED = "LEASE_RELEASE_FAILED"
    COMPENSATED = "COMPENSATED"
    QUARANTINED = "QUARANTINED"


class SpawnPhase(str, Enum):
    REQUESTED = "REQUESTED"
    CLAIMED = "CLAIMED"
    OFFER_VALIDATED = "OFFER_VALIDATED"
    LEASE_RESERVED = "LEASE_RESERVED"
    PROJECTED = "PROJECTED"
    HOME_COMMITTED = "HOME_COMMITTED"
    REGISTRY_RESERVED = "REGISTRY_RESERVED"
    START_GRANTED = "START_GRANTED"
    RUNNING = "RUNNING"
    DRAINING = "DRAINING"
    CHECKPOINTED = "CHECKPOINTED"
    STOPPED = "STOPPED"
    DENIED = "DENIED"
    ROLLED_BACK = "ROLLED_BACK"
    QUARANTINED = "QUARANTINED"


_NEXT_PHASES: Final = {
    SpawnPhase.REQUESTED: frozenset({SpawnPhase.DENIED}),
    SpawnPhase.CLAIMED: frozenset({SpawnPhase.OFFER_VALIDATED, SpawnPhase.DENIED}),
    SpawnPhase.OFFER_VALIDATED: frozenset(
        {SpawnPhase.LEASE_RESERVED, SpawnPhase.DENIED}
    ),
    SpawnPhase.LEASE_RESERVED: frozenset(
        {
            SpawnPhase.PROJECTED,
            SpawnPhase.ROLLED_BACK,
            SpawnPhase.QUARANTINED,
        }
    ),
    SpawnPhase.PROJECTED: frozenset(
        {
            SpawnPhase.HOME_COMMITTED,
            SpawnPhase.ROLLED_BACK,
            SpawnPhase.QUARANTINED,
        }
    ),
    SpawnPhase.HOME_COMMITTED: frozenset(
        {
            SpawnPhase.REGISTRY_RESERVED,
            SpawnPhase.ROLLED_BACK,
            SpawnPhase.QUARANTINED,
        }
    ),
    SpawnPhase.REGISTRY_RESERVED: frozenset(
        {
            SpawnPhase.START_GRANTED,
            SpawnPhase.ROLLED_BACK,
            SpawnPhase.QUARANTINED,
        }
    ),
    SpawnPhase.START_GRANTED: frozenset(
        {
            SpawnPhase.RUNNING,
            SpawnPhase.ROLLED_BACK,
            SpawnPhase.QUARANTINED,
        }
    ),
    SpawnPhase.RUNNING: frozenset({SpawnPhase.DRAINING, SpawnPhase.QUARANTINED}),
    SpawnPhase.DRAINING: frozenset({SpawnPhase.CHECKPOINTED, SpawnPhase.QUARANTINED}),
    SpawnPhase.CHECKPOINTED: frozenset({SpawnPhase.STOPPED, SpawnPhase.QUARANTINED}),
}


@dataclass(frozen=True, slots=True, repr=False)
class LedgerRevision(_RedactedNonSerializable):
    value: int

    def __post_init__(self) -> None:
        _require_counter(self.value, "ledger revision")


@dataclass(frozen=True, slots=True, repr=False)
class FenceEpoch(_RedactedNonSerializable):
    value: int

    def __post_init__(self) -> None:
        _require_counter(self.value, "fence epoch")


@dataclass(frozen=True, slots=True, repr=False)
class WorkerRegistryIntentV1(_RedactedNonSerializable):
    ticket_id: str
    ledger_revision: LedgerRevision
    fence_epoch: FenceEpoch

    def __post_init__(self) -> None:
        _require_text(self.ticket_id, "ticket_id")
        if type(self.ledger_revision) is not LedgerRevision:
            raise SpawnDenied("invalid ledger revision")
        if type(self.fence_epoch) is not FenceEpoch:
            raise SpawnDenied("invalid fence epoch")


@dataclass(frozen=True, slots=True, repr=False)
class WorkerFailureJournalV1(_RedactedNonSerializable):
    primary_failure_code: WorkerFailureCodeV1
    primary_failure_origin: WorkerFailureOriginV1
    compensation_status: CompensationStatusV1
    ticket_id: str
    ledger_revision: LedgerRevision
    fence_epoch: FenceEpoch

    def __post_init__(self) -> None:
        if type(self.primary_failure_code) is not WorkerFailureCodeV1:
            raise SpawnDenied("invalid primary failure code")
        if type(self.primary_failure_origin) is not WorkerFailureOriginV1:
            raise SpawnDenied("invalid primary failure origin")
        if type(self.compensation_status) is not CompensationStatusV1:
            raise SpawnDenied("invalid compensation status")
        _require_text(self.ticket_id, "ticket_id")
        if type(self.ledger_revision) is not LedgerRevision:
            raise SpawnDenied("invalid ledger revision")
        if type(self.fence_epoch) is not FenceEpoch:
            raise SpawnDenied("invalid fence epoch")


@dataclass(frozen=True, slots=True, repr=False)
class Generation(_RedactedNonSerializable):
    value: int

    def __post_init__(self) -> None:
        _require_counter(self.value, "generation")


@dataclass(frozen=True, slots=True, repr=False)
class VerifiedPrincipalV2(_RedactedNonSerializable):
    principal_id: str
    role: PrincipalRole
    authority_digest: str

    def __post_init__(self) -> None:
        _require_text(self.principal_id, "principal_id")
        if type(self.role) is not PrincipalRole:
            raise SpawnDenied("invalid principal role")
        _require_digest(self.authority_digest, "authority_digest")


@dataclass(frozen=True, slots=True, repr=False)
class LeaseBindingConsumerInputV1(_RedactedNonSerializable):
    """Exact P0 objects transported to one bound lease consumer."""

    receipt: LeaseBindingReceiptV1
    lease: CredentialLease
    allocation_ticket: ValidatedAllocationTicket
    capacity_evidence: CapacityEvidence

    def __post_init__(self) -> None:
        if type(self.receipt) is not LeaseBindingReceiptV1:
            raise SpawnDenied("lease binding verification denied")
        if type(self.lease) is not CredentialLease:
            raise SpawnDenied("lease binding verification denied")
        if type(self.allocation_ticket) is not ValidatedAllocationTicket:
            raise SpawnDenied("lease binding verification denied")
        if type(self.capacity_evidence) is not CapacityEvidence:
            raise SpawnDenied("lease binding verification denied")

    def __copy__(self) -> object:
        raise TypeError("worker spawn ledger internals are not serializable")

    def __deepcopy__(self, _memo: object) -> object:
        raise TypeError("worker spawn ledger internals are not serializable")


@dataclass(frozen=True, slots=True, repr=False)
class WorkerSpawnTicketV2(_RedactedNonSerializable):
    ticket_id: str
    request_id: str
    requester_principal_id: str
    requester_authority_digest: str
    work_package_id: str
    topic_digest: str
    target_class_id: str
    authorized_teamlead_id: str
    authorized_teamlead_authority_digest: str
    resolution_decision_digest: str
    resolution_generation: Generation
    policy_digest: str
    policy_generation: Generation
    lifecycle: WorkerLifecycle
    resume_requirement: bool
    fence_epoch: FenceEpoch
    ledger_revision: LedgerRevision
    phase: SpawnPhase
    claimed_by_principal_id: str | None = None
    lease_binding_reference: LeaseBindingReferenceV1 | None = None
    account_binding_digest: str | None = None
    source_resume_capsule_digest: str | None = None
    source_resume_capsule_generation: CapsuleGeneration | None = None
    topic_resume_binding: str | None = None
    source_resume_policy_digest: str | None = None
    source_resume_account_binding_digest: str | None = None
    resume_capsule_digest: str | None = None
    resume_capsule_generation: CapsuleGeneration | None = None

    def __post_init__(self) -> None:
        _require_text(self.ticket_id, "ticket_id")
        _require_text(self.request_id, "request_id")
        _require_text(self.requester_principal_id, "requester_principal_id")
        _require_digest(self.requester_authority_digest, "requester_authority_digest")
        _require_text(self.work_package_id, "work_package_id")
        _require_digest(self.topic_digest, "topic_digest")
        _require_text(self.target_class_id, "target_class_id")
        _require_text(self.authorized_teamlead_id, "authorized_teamlead_id")
        _require_digest(
            self.authorized_teamlead_authority_digest,
            "authorized_teamlead_authority_digest",
        )
        _require_digest(self.resolution_decision_digest, "resolution_decision_digest")
        if type(self.resolution_generation) is not Generation:
            raise SpawnDenied("invalid resolution generation")
        _require_digest(self.policy_digest, "policy_digest")
        if type(self.policy_generation) is not Generation:
            raise SpawnDenied("invalid policy generation")
        if type(self.lifecycle) is not WorkerLifecycle:
            raise SpawnDenied("invalid lifecycle")
        if type(self.resume_requirement) is not bool:
            raise SpawnDenied("invalid resume requirement")
        if type(self.fence_epoch) is not FenceEpoch:
            raise SpawnDenied("invalid fence epoch")
        if (
            type(self.ledger_revision) is not LedgerRevision
            or self.ledger_revision.value < 1
        ):
            raise SpawnDenied("invalid ledger revision")
        if type(self.phase) is not SpawnPhase:
            raise SpawnDenied("invalid spawn phase")
        if self.claimed_by_principal_id is not None:
            _require_text(self.claimed_by_principal_id, "claimed_by_principal_id")
        self._validate_optional_binding_pair(
            self.lease_binding_reference,
            self.account_binding_digest,
            "lease",
        )
        self._validate_optional_binding_pair(
            self.source_resume_capsule_digest,
            self.source_resume_capsule_generation,
            "source resume capsule",
        )
        if self.source_resume_capsule_digest is None:
            if any(
                binding is not None
                for binding in (
                    self.topic_resume_binding,
                    self.source_resume_policy_digest,
                    self.source_resume_account_binding_digest,
                )
            ):
                raise SpawnDenied("orphan source resume binding")
        else:
            _require_digest(self.topic_resume_binding, "topic_resume_binding")
            _require_digest(
                self.source_resume_policy_digest,
                "source_resume_policy_digest",
            )
            _require_digest(
                self.source_resume_account_binding_digest,
                "source_resume_account_binding_digest",
            )
        self._validate_optional_binding_pair(
            self.resume_capsule_digest,
            self.resume_capsule_generation,
            "resume capsule",
        )

    @staticmethod
    def _validate_optional_binding_pair(
        reference: object | None, account_binding: object | None, field: str
    ) -> None:
        if (reference is None) != (account_binding is None):
            raise SpawnDenied(f"incomplete {field} binding")
        if reference is None:
            return
        if field == "lease":
            if type(reference) is not LeaseBindingReferenceV1:
                raise SpawnDenied("invalid lease binding reference")
            _require_digest(account_binding, "account_binding_digest")
        elif type(account_binding) is not CapsuleGeneration:
            raise SpawnDenied("invalid capsule generation")


@dataclass(frozen=True, slots=True, repr=False)
class SpawnLedgerStateV2(_RedactedNonSerializable):
    state_revision: LedgerRevision
    tickets: tuple[WorkerSpawnTicketV2, ...]
    consumed_capsule_digests: tuple[str, ...]
    used_lease_binding_references: tuple[LeaseBindingReferenceV1, ...]
    registry_intents: tuple[WorkerRegistryIntentV1, ...] = ()
    failure_journals: tuple[WorkerFailureJournalV1, ...] = ()

    def __post_init__(self) -> None:
        if type(self.state_revision) is not LedgerRevision:
            raise SpawnDenied("invalid state revision")
        if type(self.tickets) is not tuple or any(
            type(ticket) is not WorkerSpawnTicketV2 for ticket in self.tickets
        ):
            raise SpawnDenied("invalid ledger tickets")
        if len({ticket.request_id for ticket in self.tickets}) != len(self.tickets):
            raise SpawnDenied("duplicate request in ledger state")
        self._validate_digest_tuple(
            self.consumed_capsule_digests, "consumed capsule digests"
        )
        self._validate_reference_tuple(
            self.used_lease_binding_references, "used lease binding references"
        )
        self._validate_record_tuple(
            self.registry_intents,
            WorkerRegistryIntentV1,
            "registry intents",
        )
        self._validate_record_tuple(
            self.failure_journals,
            WorkerFailureJournalV1,
            "failure journals",
        )

    @staticmethod
    def _validate_digest_tuple(values: object, field: str) -> None:
        if type(values) is not tuple:
            raise SpawnDenied(f"invalid {field}")
        for value in values:
            _require_digest(value, field)
        if len(set(values)) != len(values):
            raise SpawnDenied(f"duplicate {field}")

    @staticmethod
    def _validate_reference_tuple(values: object, field: str) -> None:
        if type(values) is not tuple:
            raise SpawnDenied(f"invalid {field}")
        for value in values:
            if type(value) is not LeaseBindingReferenceV1:
                raise SpawnDenied(f"invalid {field}")
        if len(set(values)) != len(values):
            raise SpawnDenied(f"duplicate {field}")

    @staticmethod
    def _validate_record_tuple(
        values: object, record_type: type[object], field: str
    ) -> None:
        if type(values) is not tuple or any(
            type(value) is not record_type for value in values
        ):
            raise SpawnDenied(f"invalid {field}")
        ticket_ids = tuple(value.ticket_id for value in values)
        if len(set(ticket_ids)) != len(ticket_ids):
            raise SpawnDenied(f"duplicate {field}")

    @classmethod
    def empty(cls) -> SpawnLedgerStateV2:
        return cls(
            state_revision=LedgerRevision(0),
            tickets=(),
            consumed_capsule_digests=(),
            used_lease_binding_references=(),
            registry_intents=(),
            failure_journals=(),
        )


class SpawnLedgerStatePort(ABC):
    """Injected aggregate read/CAS boundary; backend owns cross-instance atomicity."""

    @abstractmethod
    def read(self) -> SpawnLedgerStateV2:
        raise NotImplementedError

    @abstractmethod
    def compare_and_swap(
        self,
        expected_revision: LedgerRevision,
        replacement: SpawnLedgerStateV2,
    ) -> bool:
        raise NotImplementedError


class WorkerSpawnLedger(ResumeTransactionPort):
    """Fail-closed spawn state machine with no storage or runtime I/O."""

    __slots__ = ("_allocator", "_delegable_class_ids", "_state_port")

    def __init__(
        self,
        *,
        state_port: SpawnLedgerStatePort,
        delegable_nonleadership_class_ids: frozenset[str],
        allocator: RuntimeAccountAllocator,
    ) -> None:
        if not isinstance(state_port, SpawnLedgerStatePort):
            raise SpawnDenied("nominal spawn ledger state port required")
        if type(delegable_nonleadership_class_ids) is not frozenset or not (
            delegable_nonleadership_class_ids
        ):
            raise SpawnDenied("invalid delegable class set")
        if any(
            type(class_id) is not str or not class_id
            for class_id in delegable_nonleadership_class_ids
        ):
            raise SpawnDenied("invalid delegable class set")
        if type(allocator) is not RuntimeAccountAllocator:
            raise SpawnDenied("runtime account allocator required")
        self._allocator = allocator
        self._state_port = state_port
        self._delegable_class_ids = delegable_nonleadership_class_ids

    def __len__(self) -> int:
        return len(self._read_state().tickets)

    def read(self, request_id: object) -> WorkerSpawnTicketV2 | None:
        request_id = _require_text(request_id, "request_id")
        return self._find_ticket(self._read_state(), request_id)

    def publish_requested(
        self,
        *,
        request_id: object,
        requester: object,
        work_package_id: object,
        topic_digest: object,
        target_class_id: object,
        authorized_teamlead: object,
        resolution_decision_digest: object,
        resolution_generation: object,
        policy_digest: object,
        policy_generation: object,
        lifecycle: object,
        resume_requirement: object,
        fence_epoch: object,
    ) -> WorkerSpawnTicketV2:
        request_id = _require_text(request_id, "request_id")
        requester = self._require_principal(
            requester, PrincipalRole.NON_LEADERSHIP, "requester"
        )
        authorized_teamlead = self._require_principal(
            authorized_teamlead, PrincipalRole.TEAMLEADER, "teamlead"
        )
        target_class_id = _require_text(target_class_id, "target_class_id")
        if target_class_id not in self._delegable_class_ids:
            raise SpawnDenied("leadership target forbidden")
        if type(resolution_generation) is not Generation:
            raise SpawnDenied("invalid resolution generation")
        if type(policy_generation) is not Generation:
            raise SpawnDenied("invalid policy generation")
        if type(lifecycle) is not WorkerLifecycle:
            raise SpawnDenied("invalid lifecycle")
        if type(resume_requirement) is not bool:
            raise SpawnDenied("invalid resume requirement")
        if type(fence_epoch) is not FenceEpoch:
            raise SpawnDenied("invalid fence epoch")

        state = self._read_state()
        if self._find_ticket(state, request_id) is not None:
            raise SpawnDenied("request replay")
        ticket = WorkerSpawnTicketV2(
            ticket_id=f"ticket:{request_id}",
            request_id=request_id,
            requester_principal_id=requester.principal_id,
            requester_authority_digest=requester.authority_digest,
            work_package_id=_require_text(work_package_id, "work_package_id"),
            topic_digest=_require_digest(topic_digest, "topic_digest"),
            target_class_id=target_class_id,
            authorized_teamlead_id=authorized_teamlead.principal_id,
            authorized_teamlead_authority_digest=(authorized_teamlead.authority_digest),
            resolution_decision_digest=_require_digest(
                resolution_decision_digest, "resolution_decision_digest"
            ),
            resolution_generation=resolution_generation,
            policy_digest=_require_digest(policy_digest, "policy_digest"),
            policy_generation=policy_generation,
            lifecycle=lifecycle,
            resume_requirement=resume_requirement,
            fence_epoch=fence_epoch,
            ledger_revision=LedgerRevision(1),
            phase=SpawnPhase.REQUESTED,
        )
        self._commit(state, tickets=state.tickets + (ticket,))
        return ticket

    def claim(
        self,
        request_id: object,
        *,
        teamlead: object,
        expected_revision: object,
    ) -> WorkerSpawnTicketV2:
        request_id = _require_text(request_id, "request_id")
        teamlead = self._require_principal(
            teamlead, PrincipalRole.TEAMLEADER, "teamlead"
        )
        if type(expected_revision) is not LedgerRevision:
            raise SpawnDenied("invalid expected revision")
        state = self._read_state()
        ticket = self._require_ticket(state, request_id)
        self._require_revision(ticket, expected_revision)
        self._require_teamlead(ticket, teamlead)
        if ticket.phase is not SpawnPhase.REQUESTED:
            raise SpawnDenied("request already claimed or terminal")

        claimed = self._advance_ticket(
            ticket,
            phase=SpawnPhase.CLAIMED,
            claimed_by_principal_id=teamlead.principal_id,
        )
        self._commit(state, tickets=self._replace_ticket(state, claimed))
        return claimed

    def record_registry_intent(
        self,
        ticket: object,
        *,
        expected_revision: object,
        expected_fence_epoch: object,
        teamlead: object,
    ) -> WorkerSpawnTicketV2:
        ticket = self._require_ticket_value(ticket)
        if type(expected_revision) is not LedgerRevision:
            raise SpawnDenied("invalid expected revision")
        if type(expected_fence_epoch) is not FenceEpoch:
            raise SpawnDenied("invalid expected fence")
        teamlead = self._require_principal(
            teamlead, PrincipalRole.TEAMLEADER, "teamlead"
        )
        state = self._read_state()
        current = self._require_current_ticket(state, ticket)
        self._require_revision(current, expected_revision)
        self._require_fence(current, expected_fence_epoch)
        self._require_teamlead(current, teamlead)
        if self._find_registry_intent(state, current.ticket_id) is not None:
            raise SpawnDenied("intent replay")

        advanced = self._advance_ticket(current)
        intent = WorkerRegistryIntentV1(
            ticket_id=advanced.ticket_id,
            ledger_revision=advanced.ledger_revision,
            fence_epoch=advanced.fence_epoch,
        )
        self._commit(
            state,
            tickets=self._replace_ticket(state, advanced),
            registry_intents=state.registry_intents + (intent,),
        )
        return advanced

    def record_failure(
        self,
        ticket: object,
        *,
        primary_failure_code: object,
        primary_failure_origin: object,
        compensation_status: object,
        expected_revision: object,
        expected_fence_epoch: object,
        teamlead: object,
    ) -> WorkerSpawnTicketV2:
        ticket = self._require_ticket_value(ticket)
        if type(primary_failure_code) is not WorkerFailureCodeV1:
            raise SpawnDenied("invalid primary failure code")
        if type(primary_failure_origin) is not WorkerFailureOriginV1:
            raise SpawnDenied("invalid primary failure origin")
        if type(compensation_status) is not CompensationStatusV1:
            raise SpawnDenied("invalid compensation status")
        if type(expected_revision) is not LedgerRevision:
            raise SpawnDenied("invalid expected revision")
        if type(expected_fence_epoch) is not FenceEpoch:
            raise SpawnDenied("invalid expected fence")
        teamlead = self._require_principal(
            teamlead, PrincipalRole.TEAMLEADER, "teamlead"
        )
        state = self._read_state()
        current = self._require_current_ticket(state, ticket)
        self._require_revision(current, expected_revision)
        self._require_fence(current, expected_fence_epoch)
        self._require_teamlead(current, teamlead)
        if self._find_failure_journal(state, current.ticket_id) is not None:
            raise SpawnDenied("failure journal replay")

        expected_origin = {
            WorkerFailureCodeV1.PRE_A3_FAILURE: WorkerFailureOriginV1.PRE_A3,
            WorkerFailureCodeV1.A3_EXECUTION_FAILED_OR_UNKNOWN: (
                WorkerFailureOriginV1.A3_ENTERED
            ),
            WorkerFailureCodeV1.START_STATE_UNKNOWN: (
                WorkerFailureOriginV1.RECOVERY_UNKNOWN
            ),
        }[primary_failure_code]
        if primary_failure_origin is not expected_origin:
            raise SpawnDenied("primary failure binding denied")
        if primary_failure_origin is WorkerFailureOriginV1.PRE_A3:
            if compensation_status is not CompensationStatusV1.REGISTRY_RELEASE_PENDING:
                raise SpawnDenied("invalid initial compensation status")
        elif compensation_status is not CompensationStatusV1.QUARANTINED:
            raise SpawnDenied("invalid initial compensation status")

        advanced = self._advance_ticket(current)
        journal = WorkerFailureJournalV1(
            primary_failure_code=primary_failure_code,
            primary_failure_origin=primary_failure_origin,
            compensation_status=compensation_status,
            ticket_id=advanced.ticket_id,
            ledger_revision=advanced.ledger_revision,
            fence_epoch=advanced.fence_epoch,
        )
        self._commit(
            state,
            tickets=self._replace_ticket(state, advanced),
            failure_journals=state.failure_journals + (journal,),
        )
        return advanced

    def advance_compensation_status(
        self,
        ticket: object,
        *,
        compensation_status: object,
        expected_revision: object,
        expected_fence_epoch: object,
        teamlead: object,
    ) -> WorkerSpawnTicketV2:
        ticket = self._require_ticket_value(ticket)
        if type(compensation_status) is not CompensationStatusV1:
            raise SpawnDenied("invalid compensation status")
        if type(expected_revision) is not LedgerRevision:
            raise SpawnDenied("invalid expected revision")
        if type(expected_fence_epoch) is not FenceEpoch:
            raise SpawnDenied("invalid expected fence")
        teamlead = self._require_principal(
            teamlead, PrincipalRole.TEAMLEADER, "teamlead"
        )
        state = self._read_state()
        current = self._require_current_ticket(state, ticket)
        self._require_revision(current, expected_revision)
        self._require_fence(current, expected_fence_epoch)
        self._require_teamlead(current, teamlead)
        journal = self._find_failure_journal(state, current.ticket_id)
        if journal is None:
            raise SpawnDenied("failure journal required")
        if (
            journal.fence_epoch != current.fence_epoch
            or journal.ledger_revision.value > current.ledger_revision.value
        ):
            raise SpawnDenied("failure journal drift")

        allowed_statuses = {
            CompensationStatusV1.REGISTRY_RELEASE_PENDING: frozenset(
                {
                    CompensationStatusV1.REGISTRY_RELEASED,
                    CompensationStatusV1.QUARANTINED,
                }
            ),
            CompensationStatusV1.REGISTRY_RELEASED: frozenset(
                {
                    CompensationStatusV1.COMPENSATED,
                    CompensationStatusV1.HOME_RELEASE_FAILED,
                    CompensationStatusV1.LEASE_RELEASE_FAILED,
                    CompensationStatusV1.QUARANTINED,
                }
            ),
            CompensationStatusV1.HOME_RELEASE_FAILED: frozenset(
                {CompensationStatusV1.QUARANTINED}
            ),
            CompensationStatusV1.LEASE_RELEASE_FAILED: frozenset(
                {CompensationStatusV1.QUARANTINED}
            ),
        }.get(journal.compensation_status, frozenset())
        if compensation_status not in allowed_statuses:
            raise SpawnDenied("illegal compensation transition")

        advanced = self._advance_ticket(current)
        replacement = replace(
            journal,
            compensation_status=compensation_status,
            ledger_revision=advanced.ledger_revision,
            fence_epoch=advanced.fence_epoch,
        )
        self._commit(
            state,
            tickets=self._replace_ticket(state, advanced),
            failure_journals=self._replace_failure_journal(state, replacement),
        )
        return advanced

    def append_phase(
        self,
        ticket: object,
        phase: object,
        *,
        expected_revision: object,
        expected_fence_epoch: object,
        teamlead: object,
        lease_binding: object | None = None,
    ) -> WorkerSpawnTicketV2:
        ticket = self._require_ticket_value(ticket)
        if type(phase) is not SpawnPhase:
            raise SpawnDenied("unknown phase")
        if type(expected_revision) is not LedgerRevision:
            raise SpawnDenied("invalid expected revision")
        if type(expected_fence_epoch) is not FenceEpoch:
            raise SpawnDenied("invalid expected fence")
        teamlead = self._require_principal(
            teamlead, PrincipalRole.TEAMLEADER, "teamlead"
        )
        state = self._read_state()
        current = self._require_current_ticket(state, ticket)
        self._require_revision(current, expected_revision)
        self._require_fence(current, expected_fence_epoch)
        self._require_teamlead(current, teamlead)
        if phase not in _NEXT_PHASES.get(current.phase, frozenset()):
            raise SpawnDenied("illegal phase transition")
        failure_journal = self._find_failure_journal(state, current.ticket_id)
        if (
            phase is SpawnPhase.ROLLED_BACK
            and failure_journal is not None
            and (
                failure_journal.ledger_revision != current.ledger_revision
                or failure_journal.fence_epoch != current.fence_epoch
                or failure_journal.primary_failure_origin
                is not WorkerFailureOriginV1.PRE_A3
                or failure_journal.compensation_status
                is not CompensationStatusV1.COMPENSATED
            )
        ):
            raise SpawnDenied("rollback failure journal denied")
        if (
            phase is SpawnPhase.QUARANTINED
            and failure_journal is not None
            and (
                failure_journal.ledger_revision != current.ledger_revision
                or failure_journal.fence_epoch != current.fence_epoch
                or failure_journal.compensation_status
                is not CompensationStatusV1.QUARANTINED
            )
        ):
            raise SpawnDenied("quarantine failure journal denied")

        used_references = state.used_lease_binding_references
        changes: dict[str, object] = {"phase": phase}
        verification = None
        primary: BaseException | None = None
        try:
            if phase is SpawnPhase.LEASE_RESERVED:
                if type(lease_binding) is not LeaseBindingConsumerInputV1:
                    raise SpawnDenied("lease binding verification denied")
                self._require_allocation_ticket(current, lease_binding)
                try:
                    verification = self._allocator.verify_lease_binding_receipt(
                        lease_binding.receipt,
                        expected_lease=lease_binding.lease,
                        expected_ticket=lease_binding.allocation_ticket,
                        expected_capacity_evidence=lease_binding.capacity_evidence,
                    )
                    reference = self._allocator.lease_binding_reference_for(
                        verification
                    )
                except AllocationDenied as exc:
                    raise SpawnDenied("lease binding verification denied") from exc
                if type(reference) is not LeaseBindingReferenceV1:
                    raise SpawnDenied("lease binding verification denied")
                if reference in used_references:
                    raise SpawnDenied("lease binding replay")
                changes.update(
                    lease_binding_reference=reference,
                    account_binding_digest=str(
                        lease_binding.lease.account_binding_digest
                    ),
                )
                used_references += (reference,)
            elif lease_binding is not None:
                raise SpawnDenied("unexpected lease binding")

            if phase in {
                SpawnPhase.ROLLED_BACK,
                SpawnPhase.CHECKPOINTED,
                SpawnPhase.STOPPED,
            }:
                self._require_terminal_binding(current)

            advanced = self._advance_ticket(current, **changes)
            self._commit(
                state,
                tickets=self._replace_ticket(state, advanced),
                used_lease_binding_references=used_references,
            )
            return advanced
        except BaseException as exc:
            primary = exc
            raise
        finally:
            if verification is not None:
                try:
                    self._allocator.close_lease_binding_verification(verification)
                except AllocationDenied as close_error:
                    if primary is None:
                        raise SpawnDenied(
                            "lease binding verification denied"
                        ) from close_error
                    primary.add_note(
                        "lease binding guard close denied; quarantine required"
                    )

    def bind_resume_capsule(
        self,
        ticket: object,
        capsule: object,
        *,
        expected_revision: object,
        expected_fence_epoch: object,
        teamlead: object,
    ) -> WorkerSpawnTicketV2:
        ticket = self._require_ticket_value(ticket)
        if type(capsule) is not WorkerResumeCapsuleV2:
            raise SpawnDenied("worker resume capsule v2 required")
        if type(expected_revision) is not LedgerRevision:
            raise SpawnDenied("invalid expected revision")
        if type(expected_fence_epoch) is not FenceEpoch:
            raise SpawnDenied("invalid expected fence")
        teamlead = self._require_principal(
            teamlead, PrincipalRole.TEAMLEADER, "teamlead"
        )
        state = self._read_state()
        current = self._require_current_ticket(state, ticket)
        self._require_revision(current, expected_revision)
        self._require_fence(current, expected_fence_epoch)
        self._require_teamlead(current, teamlead)
        if current.phase not in {
            SpawnPhase.LEASE_RESERVED,
            SpawnPhase.PROJECTED,
            SpawnPhase.HOME_COMMITTED,
            SpawnPhase.REGISTRY_RESERVED,
            SpawnPhase.START_GRANTED,
            SpawnPhase.RUNNING,
            SpawnPhase.DRAINING,
        }:
            raise SpawnDenied("capsule cannot bind in current phase")
        if current.account_binding_digest is None:
            raise SpawnDenied("account binding required before capsule")
        try:
            require_terminal_capsule(
                lifecycle=current.lifecycle,
                resumable=current.resume_requirement,
                capsule=capsule,
                topic_digest=current.topic_digest,
                policy_digest=current.policy_digest,
                account_binding_digest=current.account_binding_digest,
            )
        except ResumeDenied as exc:
            raise SpawnDenied("resume capsule binding denied") from exc
        if current.resume_capsule_digest is not None:
            raise SpawnDenied("ticket already has resume capsule")
        if capsule.capsule_digest in state.consumed_capsule_digests or any(
            other.resume_capsule_digest == capsule.capsule_digest
            for other in state.tickets
        ):
            raise SpawnDenied("resume capsule replay")

        bound = self._advance_ticket(
            current,
            resume_capsule_digest=capsule.capsule_digest,
            resume_capsule_generation=capsule.capsule_generation,
        )
        self._commit(state, tickets=self._replace_ticket(state, bound))
        return bound

    def claim_resume_capsule(
        self,
        source_ticket: object,
        capsule: WorkerResumeCapsuleV2,
        *,
        new_request_id: object,
        new_fence_epoch: object,
        expected_revision: object,
        expected_capsule_generation: object,
        teamlead: object,
    ) -> WorkerResumeRequestV2:
        source_ticket = self._require_ticket_value(source_ticket)
        if type(capsule) is not WorkerResumeCapsuleV2:
            raise SpawnDenied("worker resume capsule v2 required")
        new_request_id = _require_text(new_request_id, "new_request_id")
        if type(new_fence_epoch) is not FenceEpoch:
            raise SpawnDenied("invalid new fence")
        if type(expected_revision) is not LedgerRevision:
            raise SpawnDenied("invalid expected revision")
        if type(expected_capsule_generation) is not CapsuleGeneration:
            raise SpawnDenied("invalid expected capsule generation")
        teamlead = self._require_principal(
            teamlead, PrincipalRole.TEAMLEADER, "teamlead"
        )

        state = self._read_state()
        current = self._require_current_ticket(state, source_ticket)
        self._require_revision(current, expected_revision)
        self._require_teamlead(current, teamlead)
        if current.phase is not SpawnPhase.CHECKPOINTED:
            raise SpawnDenied("resume requires checkpointed source")
        if new_fence_epoch.value <= current.fence_epoch.value:
            raise SpawnDenied("resume fence must advance")
        if self._find_ticket(state, new_request_id) is not None:
            raise SpawnDenied("new request replay")
        if (
            current.resume_capsule_digest != capsule.capsule_digest
            or current.resume_capsule_generation != capsule.capsule_generation
            or expected_capsule_generation != capsule.capsule_generation
            or current.topic_digest != capsule.topic_digest
            or current.policy_digest != capsule.policy_digest
            or current.account_binding_digest != capsule.account_binding_digest
        ):
            raise SpawnDenied("resume capsule binding drift")
        if capsule.capsule_digest in state.consumed_capsule_digests:
            raise SpawnDenied("resume capsule already consumed")

        requested = WorkerSpawnTicketV2(
            ticket_id=f"ticket:{new_request_id}",
            request_id=new_request_id,
            requester_principal_id=current.requester_principal_id,
            requester_authority_digest=current.requester_authority_digest,
            work_package_id=current.work_package_id,
            topic_digest=current.topic_digest,
            target_class_id=current.target_class_id,
            authorized_teamlead_id=current.authorized_teamlead_id,
            authorized_teamlead_authority_digest=(
                current.authorized_teamlead_authority_digest
            ),
            resolution_decision_digest=current.resolution_decision_digest,
            resolution_generation=current.resolution_generation,
            policy_digest=current.policy_digest,
            policy_generation=current.policy_generation,
            lifecycle=current.lifecycle,
            resume_requirement=current.resume_requirement,
            fence_epoch=new_fence_epoch,
            ledger_revision=LedgerRevision(1),
            phase=SpawnPhase.REQUESTED,
            source_resume_capsule_digest=capsule.capsule_digest,
            source_resume_capsule_generation=capsule.capsule_generation,
            topic_resume_binding=capsule.topic_digest,
            source_resume_policy_digest=capsule.policy_digest,
            source_resume_account_binding_digest=capsule.account_binding_digest,
        )
        self._commit(
            state,
            tickets=state.tickets + (requested,),
            consumed_capsule_digests=(
                state.consumed_capsule_digests + (capsule.capsule_digest,)
            ),
        )
        return WorkerResumeRequestV2(
            request_id=requested.request_id,
            capsule_digest=capsule.capsule_digest,
            capsule_generation=capsule.capsule_generation,
            bee_digest=capsule.bee_digest,
            session_digest=capsule.session_digest,
            topic_digest=capsule.topic_digest,
            policy_digest=capsule.policy_digest,
            account_binding_digest=capsule.account_binding_digest,
            phase=ResumeRequestPhase.REQUESTED,
            requested_revision=1,
            requires_new_lease=True,
            allows_in_place_credential_rotation=False,
        )

    def _read_state(self) -> SpawnLedgerStateV2:
        try:
            state = self._state_port.read()
        except Exception as exc:
            raise SpawnDenied("ledger read failed") from exc
        if type(state) is not SpawnLedgerStateV2:
            raise SpawnDenied("invalid ledger state")
        return state

    def _commit(
        self,
        state: SpawnLedgerStateV2,
        *,
        tickets: tuple[WorkerSpawnTicketV2, ...] | None = None,
        consumed_capsule_digests: tuple[str, ...] | None = None,
        used_lease_binding_references: tuple[LeaseBindingReferenceV1, ...]
        | None = None,
        registry_intents: tuple[WorkerRegistryIntentV1, ...] | None = None,
        failure_journals: tuple[WorkerFailureJournalV1, ...] | None = None,
    ) -> None:
        replacement = SpawnLedgerStateV2(
            state_revision=LedgerRevision(state.state_revision.value + 1),
            tickets=state.tickets if tickets is None else tickets,
            consumed_capsule_digests=(
                state.consumed_capsule_digests
                if consumed_capsule_digests is None
                else consumed_capsule_digests
            ),
            used_lease_binding_references=(
                state.used_lease_binding_references
                if used_lease_binding_references is None
                else used_lease_binding_references
            ),
            registry_intents=(
                state.registry_intents if registry_intents is None else registry_intents
            ),
            failure_journals=(
                state.failure_journals if failure_journals is None else failure_journals
            ),
        )
        try:
            committed = self._state_port.compare_and_swap(
                state.state_revision, replacement
            )
        except Exception as exc:
            raise SpawnDenied("ledger CAS failed") from exc
        if type(committed) is not bool or not committed:
            raise SpawnDenied("ledger CAS conflict")

    @staticmethod
    def _find_ticket(
        state: SpawnLedgerStateV2, request_id: str
    ) -> WorkerSpawnTicketV2 | None:
        return next(
            (ticket for ticket in state.tickets if ticket.request_id == request_id),
            None,
        )

    @staticmethod
    def _find_registry_intent(
        state: SpawnLedgerStateV2, ticket_id: str
    ) -> WorkerRegistryIntentV1 | None:
        return next(
            (
                intent
                for intent in state.registry_intents
                if intent.ticket_id == ticket_id
            ),
            None,
        )

    @staticmethod
    def _find_failure_journal(
        state: SpawnLedgerStateV2, ticket_id: str
    ) -> WorkerFailureJournalV1 | None:
        return next(
            (
                journal
                for journal in state.failure_journals
                if journal.ticket_id == ticket_id
            ),
            None,
        )

    @classmethod
    def _require_ticket(
        cls, state: SpawnLedgerStateV2, request_id: str
    ) -> WorkerSpawnTicketV2:
        ticket = cls._find_ticket(state, request_id)
        if ticket is None:
            raise SpawnDenied("unknown request")
        return ticket

    @staticmethod
    def _require_ticket_value(ticket: object) -> WorkerSpawnTicketV2:
        if type(ticket) is not WorkerSpawnTicketV2:
            raise SpawnDenied("invalid ticket")
        return ticket

    @classmethod
    def _require_current_ticket(
        cls, state: SpawnLedgerStateV2, ticket: WorkerSpawnTicketV2
    ) -> WorkerSpawnTicketV2:
        current = cls._require_ticket(state, ticket.request_id)
        if current != ticket:
            raise SpawnDenied("ticket revision or phase drift")
        return current

    @staticmethod
    def _require_principal(
        principal: object, role: PrincipalRole, field: str
    ) -> VerifiedPrincipalV2:
        if type(principal) is not VerifiedPrincipalV2 or principal.role is not role:
            raise SpawnDenied(f"invalid {field} authority")
        return principal

    @staticmethod
    def _require_teamlead(
        ticket: WorkerSpawnTicketV2, teamlead: VerifiedPrincipalV2
    ) -> None:
        if (
            teamlead.principal_id != ticket.authorized_teamlead_id
            or teamlead.authority_digest != ticket.authorized_teamlead_authority_digest
        ):
            raise SpawnDenied("teamlead authority denied")
        if (
            ticket.claimed_by_principal_id is not None
            and ticket.claimed_by_principal_id != teamlead.principal_id
        ):
            raise SpawnDenied("ticket owner drift")

    @staticmethod
    def _require_revision(
        ticket: WorkerSpawnTicketV2, revision: LedgerRevision
    ) -> None:
        if ticket.ledger_revision != revision:
            raise SpawnDenied("ledger revision drift")

    @staticmethod
    def _require_fence(ticket: WorkerSpawnTicketV2, fence: FenceEpoch) -> None:
        if ticket.fence_epoch != fence:
            raise SpawnDenied("fence drift")

    @staticmethod
    def _replace_ticket(
        state: SpawnLedgerStateV2, replacement: WorkerSpawnTicketV2
    ) -> tuple[WorkerSpawnTicketV2, ...]:
        return tuple(
            replacement if ticket.request_id == replacement.request_id else ticket
            for ticket in state.tickets
        )

    @staticmethod
    def _replace_failure_journal(
        state: SpawnLedgerStateV2, replacement: WorkerFailureJournalV1
    ) -> tuple[WorkerFailureJournalV1, ...]:
        return tuple(
            replacement if journal.ticket_id == replacement.ticket_id else journal
            for journal in state.failure_journals
        )

    @staticmethod
    def _advance_ticket(
        ticket: WorkerSpawnTicketV2, **changes: object
    ) -> WorkerSpawnTicketV2:
        return replace(
            ticket,
            ledger_revision=LedgerRevision(ticket.ledger_revision.value + 1),
            **changes,
        )

    @staticmethod
    def _require_terminal_binding(ticket: WorkerSpawnTicketV2) -> None:
        capsule_required = ticket.resume_requirement or ticket.lifecycle in {
            WorkerLifecycle.BINDING,
            WorkerLifecycle.PERSISTENT,
        }
        if capsule_required and (
            ticket.resume_capsule_digest is None
            or ticket.resume_capsule_generation is None
        ):
            raise SpawnDenied("terminal capsule binding required")

    @staticmethod
    def _require_allocation_ticket(
        current: WorkerSpawnTicketV2,
        binding: LeaseBindingConsumerInputV1,
    ) -> None:
        allocation_ticket = binding.allocation_ticket
        try:
            decision_digest = canonical_resolution_decision_digest(
                allocation_ticket.resolution_decision
            )
        except ValueError as exc:
            raise SpawnDenied("lease binding verification denied") from exc
        if (
            current.phase is not SpawnPhase.OFFER_VALIDATED
            or allocation_ticket.phase != "OFFER_VALIDATED"
            or allocation_ticket.ticket_id != current.ticket_id
            or allocation_ticket.ledger_revision != current.ledger_revision.value
            or allocation_ticket.fence_epoch != current.fence_epoch.value
            or decision_digest != current.resolution_decision_digest
            or allocation_ticket.resolver_offer_generation
            != allocation_ticket.selection_offer.generation
            or allocation_ticket.resolution_decision.class_id != current.target_class_id
            or allocation_ticket.resolver_offer_generation
            != allocation_ticket.selection_offer.generation
            or allocation_ticket.policy_generation != current.policy_generation.value
            or allocation_ticket.policy_digest != current.policy_digest
            or binding.capacity_evidence.ticket_id != allocation_ticket.ticket_id
            or binding.capacity_evidence.ledger_revision
            != allocation_ticket.ledger_revision
            or binding.capacity_evidence.fence_epoch != allocation_ticket.fence_epoch
        ):
            raise SpawnDenied("lease binding verification denied")


__all__ = [
    "FenceEpoch",
    "Generation",
    "LeaseBindingConsumerInputV1",
    "LedgerRevision",
    "PrincipalRole",
    "SpawnDenied",
    "SpawnLedgerStatePort",
    "SpawnLedgerStateV2",
    "SpawnPhase",
    "VerifiedPrincipalV2",
    "WorkerLifecycle",
    "WorkerSpawnLedger",
    "WorkerSpawnTicketV2",
]
