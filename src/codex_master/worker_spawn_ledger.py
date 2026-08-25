"""Local, authenticated spawn-request ledger with no runtime side effects."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from functools import wraps
import re
from threading import RLock
from typing import Final


_DIGEST_RE: Final = re.compile(r"^sha256:[0-9a-f]{64}$")
_LIFECYCLES: Final = frozenset({"ephemeral", "invocation", "binding", "persistent"})


class SpawnDenied(ValueError):
    """Raised when an authenticated spawn transaction violates its binding."""


class _RedactedNonSerializable:
    __slots__ = ()

    def __repr__(self) -> str:
        return f"<{type(self).__name__} redacted>"

    __str__ = __repr__

    def __reduce_ex__(self, _protocol: int) -> object:
        raise TypeError("worker spawn ledger internals are not serializable")


class SpawnPhase(str, Enum):
    REQUESTED = "REQUESTED"
    CLAIMED = "CLAIMED"
    OFFER_VALIDATED = "OFFER_VALIDATED"
    LEASE_RESERVED = "LEASE_RESERVED"
    HOME_ATTESTED = "HOME_ATTESTED"
    REGISTRY_COMMITTED = "REGISTRY_COMMITTED"
    START_GRANTED = "START_GRANTED"
    RUNNING = "RUNNING"
    DENIED = "DENIED"
    ROLLBACK = "ROLLBACK"
    RELEASE_PENDING = "RELEASE_PENDING"
    QUARANTINED = "QUARANTINED"


_NEXT_PHASES: Final = {
    SpawnPhase.CLAIMED: frozenset(
        {
            SpawnPhase.OFFER_VALIDATED,
            SpawnPhase.DENIED,
            SpawnPhase.ROLLBACK,
            SpawnPhase.QUARANTINED,
        }
    ),
    SpawnPhase.OFFER_VALIDATED: frozenset(
        {
            SpawnPhase.LEASE_RESERVED,
            SpawnPhase.DENIED,
            SpawnPhase.ROLLBACK,
            SpawnPhase.QUARANTINED,
        }
    ),
    SpawnPhase.LEASE_RESERVED: frozenset(
        {
            SpawnPhase.HOME_ATTESTED,
            SpawnPhase.ROLLBACK,
            SpawnPhase.RELEASE_PENDING,
            SpawnPhase.QUARANTINED,
        }
    ),
    SpawnPhase.HOME_ATTESTED: frozenset(
        {
            SpawnPhase.REGISTRY_COMMITTED,
            SpawnPhase.ROLLBACK,
            SpawnPhase.RELEASE_PENDING,
            SpawnPhase.QUARANTINED,
        }
    ),
    SpawnPhase.REGISTRY_COMMITTED: frozenset(
        {
            SpawnPhase.START_GRANTED,
            SpawnPhase.ROLLBACK,
            SpawnPhase.RELEASE_PENDING,
            SpawnPhase.QUARANTINED,
        }
    ),
    SpawnPhase.START_GRANTED: frozenset(
        {
            SpawnPhase.RUNNING,
            SpawnPhase.ROLLBACK,
            SpawnPhase.RELEASE_PENDING,
            SpawnPhase.QUARANTINED,
        }
    ),
    SpawnPhase.RUNNING: frozenset({SpawnPhase.RELEASE_PENDING, SpawnPhase.QUARANTINED}),
    SpawnPhase.RELEASE_PENDING: frozenset({SpawnPhase.QUARANTINED}),
}


@dataclass(frozen=True, slots=True, repr=False)
class WorkerSpawnTicketV2(_RedactedNonSerializable):
    ticket_id: str
    request_id: str
    requester_principal_id: str
    work_package_id: str
    topic_digest: str
    target_class_id: str
    authorized_teamlead_id: str
    authority_digest: str
    resolution_decision_digest: str
    resolution_generation: int
    policy_generation: int
    lifecycle: str
    resume_requirement: bool
    fence_epoch: int
    ledger_revision: int
    phase: SpawnPhase
    claimed_by_principal_id: str | None = None


def _require_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise SpawnDenied(f"invalid {field}")
    return value


def _require_digest(value: object, field: str) -> str:
    value = _require_text(value, field)
    if _DIGEST_RE.fullmatch(value) is None:
        raise SpawnDenied(f"invalid {field}")
    return value


def _require_non_negative_int(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise SpawnDenied(f"invalid {field}")
    return value


def _synchronized(method):
    @wraps(method)
    def wrapped(ledger, *args, **kwargs):
        with ledger._claim_lock:
            return method(ledger, *args, **kwargs)

    return wrapped


class WorkerSpawnLedger:
    """Private in-memory ledger; it never allocates, starts, or publishes externally."""

    __slots__ = ("_claim_lock", "_delegable_class_ids", "_tickets_by_request")

    def __init__(self, *, delegable_nonleadership_class_ids: frozenset[str]) -> None:
        if not isinstance(delegable_nonleadership_class_ids, frozenset) or not (
            delegable_nonleadership_class_ids
        ):
            raise SpawnDenied("invalid delegable class set")
        if any(
            not isinstance(class_id, str) or not class_id
            for class_id in delegable_nonleadership_class_ids
        ):
            raise SpawnDenied("invalid delegable class set")
        self._claim_lock = RLock()
        self._delegable_class_ids = delegable_nonleadership_class_ids
        self._tickets_by_request: dict[str, WorkerSpawnTicketV2] = {}

    def __len__(self) -> int:
        return len(self._tickets_by_request)

    @_synchronized
    def publish_requested(
        self,
        *,
        request_id: object,
        requester_principal_id: object,
        requester_role: object,
        work_package_id: object,
        topic_digest: object,
        target_class_id: object,
        authorized_teamlead_id: object,
        authority_digest: object,
        resolution_decision_digest: object,
        resolution_generation: object,
        policy_generation: object,
        lifecycle: object,
        resume_requirement: object,
        fence_epoch: object,
    ) -> WorkerSpawnTicketV2:
        """Accept one authenticated, non-leadership request into ``REQUESTED``."""

        request_id = _require_text(request_id, "request_id")
        if request_id in self._tickets_by_request:
            raise SpawnDenied("request replay")
        if requester_role not in {"worker", "non_leadership"}:
            raise SpawnDenied("requester not allowed to publish")
        target_class_id = _require_text(target_class_id, "target_class_id")
        if target_class_id not in self._delegable_class_ids:
            raise SpawnDenied("leadership target forbidden")
        lifecycle = _require_text(lifecycle, "lifecycle")
        if lifecycle not in _LIFECYCLES:
            raise SpawnDenied("invalid lifecycle")
        if not isinstance(resume_requirement, bool):
            raise SpawnDenied("invalid resume requirement")

        ticket = WorkerSpawnTicketV2(
            ticket_id=f"ticket:{request_id}",
            request_id=request_id,
            requester_principal_id=_require_text(
                requester_principal_id, "requester_principal_id"
            ),
            work_package_id=_require_text(work_package_id, "work_package_id"),
            topic_digest=_require_digest(topic_digest, "topic_digest"),
            target_class_id=target_class_id,
            authorized_teamlead_id=_require_text(
                authorized_teamlead_id, "authorized_teamlead_id"
            ),
            authority_digest=_require_digest(authority_digest, "authority_digest"),
            resolution_decision_digest=_require_digest(
                resolution_decision_digest, "resolution_decision_digest"
            ),
            resolution_generation=_require_non_negative_int(
                resolution_generation, "resolution_generation"
            ),
            policy_generation=_require_non_negative_int(
                policy_generation, "policy_generation"
            ),
            lifecycle=lifecycle,
            resume_requirement=resume_requirement,
            fence_epoch=_require_non_negative_int(fence_epoch, "fence_epoch"),
            ledger_revision=1,
            phase=SpawnPhase.REQUESTED,
        )
        self._tickets_by_request[request_id] = ticket
        return ticket

    @_synchronized
    def claim(
        self,
        request_id: object,
        *,
        teamlead_principal_id: object,
        expected_revision: object,
    ) -> WorkerSpawnTicketV2:
        """Claim one ticket exactly once for its pre-authorized Teamleiterin."""

        request_id = _require_text(request_id, "request_id")
        ticket = self._tickets_by_request.get(request_id)
        if ticket is None:
            raise SpawnDenied("unknown request")
        self._require_current_revision(ticket, expected_revision)
        if ticket.phase is not SpawnPhase.REQUESTED:
            raise SpawnDenied("request already claimed or terminal")
        if teamlead_principal_id != ticket.authorized_teamlead_id:
            raise SpawnDenied("teamlead authority denied")

        claimed = self._replace(
            ticket,
            phase=SpawnPhase.CLAIMED,
            claimed_by_principal_id=ticket.authorized_teamlead_id,
        )
        self._tickets_by_request[request_id] = claimed
        return claimed

    @_synchronized
    def append_phase(
        self,
        ticket: object,
        phase: object,
        *,
        expected_revision: object,
        expected_fence_epoch: object,
        teamlead_principal_id: object,
    ) -> WorkerSpawnTicketV2:
        """Append one legal phase while preserving ticket, owner, revision, and fence."""

        if not isinstance(ticket, WorkerSpawnTicketV2):
            raise SpawnDenied("invalid ticket")
        current = self._tickets_by_request.get(ticket.request_id)
        if current is None or ticket != current:
            raise SpawnDenied("ticket phase or revision drift")
        self._require_current_revision(current, expected_revision)
        if expected_fence_epoch != current.fence_epoch:
            raise SpawnDenied("fence drift")
        if teamlead_principal_id != current.claimed_by_principal_id:
            raise SpawnDenied("ticket owner drift")
        if not isinstance(phase, SpawnPhase):
            raise SpawnDenied("unknown phase")
        if phase not in _NEXT_PHASES.get(current.phase, frozenset()):
            raise SpawnDenied("illegal phase transition")

        advanced = self._replace(current, phase=phase)
        self._tickets_by_request[current.request_id] = advanced
        return advanced

    @staticmethod
    def _require_current_revision(
        ticket: WorkerSpawnTicketV2, revision: object
    ) -> None:
        if revision != ticket.ledger_revision:
            raise SpawnDenied("ledger revision drift")

    @staticmethod
    def _replace(
        ticket: WorkerSpawnTicketV2,
        *,
        phase: SpawnPhase,
        claimed_by_principal_id: str | None = None,
    ) -> WorkerSpawnTicketV2:
        return WorkerSpawnTicketV2(
            ticket_id=ticket.ticket_id,
            request_id=ticket.request_id,
            requester_principal_id=ticket.requester_principal_id,
            work_package_id=ticket.work_package_id,
            topic_digest=ticket.topic_digest,
            target_class_id=ticket.target_class_id,
            authorized_teamlead_id=ticket.authorized_teamlead_id,
            authority_digest=ticket.authority_digest,
            resolution_decision_digest=ticket.resolution_decision_digest,
            resolution_generation=ticket.resolution_generation,
            policy_generation=ticket.policy_generation,
            lifecycle=ticket.lifecycle,
            resume_requirement=ticket.resume_requirement,
            fence_epoch=ticket.fence_epoch,
            ledger_revision=ticket.ledger_revision + 1,
            phase=phase,
            claimed_by_principal_id=(
                ticket.claimed_by_principal_id
                if claimed_by_principal_id is None
                else claimed_by_principal_id
            ),
        )


__all__ = ["SpawnDenied", "SpawnPhase", "WorkerSpawnLedger", "WorkerSpawnTicketV2"]
