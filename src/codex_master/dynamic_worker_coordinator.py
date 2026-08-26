"""B5 dynamic-worker coordination up to, but excluding, A3 start."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from codex_master.fleet_registry import (
    DynamicWorkerRegistryPlannerV2,
    FleetSnapshotV2,
)
from codex_master.runtime_account_allocator import (
    CapacityEvidence,
    RuntimeAccountAllocator,
    ValidatedAllocationTicket,
)
from codex_master.worker_resolution_carrier import (
    WorkerRegistryReservationIssuerV2,
    WorkerRegistryReservationV2,
    WorkerResolutionCarrierV2,
)
from codex_master.worker_spawn_ledger import (
    CompensationStatusV1,
    LeaseBindingConsumerInputV1,
    PrincipalRole,
    SpawnLedgerStatePort,
    SpawnPhase,
    VerifiedPrincipalV2,
    WorkerFailureCodeV1,
    WorkerFailureOriginV1,
    WorkerSpawnLedger,
    WorkerSpawnTicketV2,
    _RedactedNonSerializable,
)


class DynamicWorkerCoordinatorDenied(ValueError):
    """Raised when B5 coordination cannot prove its exact bindings."""


@dataclass(frozen=True, slots=True, repr=False)
class _DynamicWorkerAllocationPortV1(_RedactedNonSerializable):
    issue: Callable[
        [WorkerSpawnTicketV2, WorkerResolutionCarrierV2],
        tuple[ValidatedAllocationTicket, CapacityEvidence],
    ]


@dataclass(frozen=True, slots=True, repr=False)
class _DynamicWorkerProjectionPortV1(_RedactedNonSerializable):
    project: Callable[
        [WorkerSpawnTicketV2, WorkerResolutionCarrierV2, LeaseBindingConsumerInputV1],
        object,
    ]


@dataclass(frozen=True, slots=True, repr=False)
class _DynamicWorkerHomePortV1(_RedactedNonSerializable):
    commit: Callable[[WorkerSpawnTicketV2, object, LeaseBindingConsumerInputV1], object]
    cleanup: Callable[[object], None]


@dataclass(frozen=True, slots=True, repr=False)
class _DynamicWorkerRegistryPortV1(_RedactedNonSerializable):
    read_snapshot: Callable[[], FleetSnapshotV2]
    compare_and_swap: Callable[..., FleetSnapshotV2]


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _PreStartAttemptV1(_RedactedNonSerializable):
    ticket: WorkerSpawnTicketV2
    lease_binding: LeaseBindingConsumerInputV1
    reservation: WorkerRegistryReservationV2
    projection_receipt: object | None = None
    home_receipt: object | None = None
    registry_before: FleetSnapshotV2 | None = None
    registry_reserved: FleetSnapshotV2 | None = None


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class PreStartReceiptV1(_RedactedNonSerializable):
    """Opaque, coordinator-bound proof that B5 completed before A3."""

    _port_token: object
    _attempt: _PreStartAttemptV1


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class DynamicWorkerPreStartPortV1(_RedactedNonSerializable):
    """Injected B5 coordinator capability with no A3 execution surface."""

    ledger: WorkerSpawnLedger
    state_port: SpawnLedgerStatePort
    allocator: RuntimeAccountAllocator
    allocation_port: _DynamicWorkerAllocationPortV1
    projection_port: _DynamicWorkerProjectionPortV1
    home_port: _DynamicWorkerHomePortV1
    registry_port: _DynamicWorkerRegistryPortV1
    teamlead: VerifiedPrincipalV2
    principal_id: str
    _token: object = field(default_factory=object, init=False, repr=False)
    _receipt_states: dict[int, str] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )

    def coordinate(
        self,
        ticket: object,
        resolution: object,
    ) -> PreStartReceiptV1:
        return coordinate_dynamic_worker_pre_start(self, ticket, resolution)

    def compensate_not_started(self, receipt: object) -> dict[str, str]:
        return compensate_dynamic_worker_not_started(self, receipt)

    def quarantine_unknown_or_started(self, receipt: object) -> dict[str, str]:
        return quarantine_dynamic_worker_unknown_or_started(self, receipt)


def coordinate_dynamic_worker_pre_start(
    port: object,
    ticket: object,
    resolution: object,
) -> PreStartReceiptV1:
    """Reserve all B5 resources once and return only after ledger acknowledgement."""

    if (
        type(port) is not DynamicWorkerPreStartPortV1
        or type(port.ledger) is not WorkerSpawnLedger
        or not isinstance(port.state_port, SpawnLedgerStatePort)
        or type(port.allocator) is not RuntimeAccountAllocator
        or type(port.allocation_port) is not _DynamicWorkerAllocationPortV1
        or type(port.projection_port) is not _DynamicWorkerProjectionPortV1
        or type(port.home_port) is not _DynamicWorkerHomePortV1
        or type(port.registry_port) is not _DynamicWorkerRegistryPortV1
        or type(port.teamlead) is not VerifiedPrincipalV2
        or port.teamlead.role is not PrincipalRole.TEAMLEADER
        or type(port.principal_id) is not str
        or not callable(port.allocation_port.issue)
        or not callable(port.projection_port.project)
        or not callable(port.home_port.commit)
        or not callable(port.home_port.cleanup)
        or not callable(port.registry_port.read_snapshot)
        or not callable(port.registry_port.compare_and_swap)
        or object.__getattribute__(port.ledger, "_state_port") is not port.state_port
        or object.__getattribute__(port.ledger, "_allocator") is not port.allocator
        or type(ticket) is not WorkerSpawnTicketV2
        or type(resolution) is not WorkerResolutionCarrierV2
    ):
        raise DynamicWorkerCoordinatorDenied("dynamic worker coordination denied")
    current = port.ledger.read(ticket.request_id)
    if (
        current is not ticket
        or ticket.phase is not SpawnPhase.CLAIMED
        or ticket.claimed_by_principal_id != port.teamlead.principal_id
        or ticket.authorized_teamlead_id != port.teamlead.principal_id
        or ticket.authorized_teamlead_authority_digest != port.teamlead.authority_digest
        or resolution.ticket_id != ticket.ticket_id
        or resolution.ticket_fence_epoch != ticket.fence_epoch
        or resolution.ticket_resolution_generation != ticket.resolution_generation
        or resolution.ticket_policy_digest != ticket.policy_digest
        or resolution.ticket_policy_generation != ticket.policy_generation
        or resolution.resolution_decision_digest != ticket.resolution_decision_digest
        or resolution.decision.class_id != ticket.target_class_id
    ):
        raise DynamicWorkerCoordinatorDenied("dynamic worker coordination denied")

    try:
        current = port.ledger.append_phase(
            current,
            SpawnPhase.OFFER_VALIDATED,
            expected_revision=current.ledger_revision,
            expected_fence_epoch=current.fence_epoch,
            teamlead=port.teamlead,
        )
        allocation_ticket, capacity_evidence = port.allocation_port.issue(
            current, resolution
        )
        if (
            type(allocation_ticket) is not ValidatedAllocationTicket
            or type(capacity_evidence) is not CapacityEvidence
        ):
            raise DynamicWorkerCoordinatorDenied("allocation evidence denied")
        lease = port.allocator.allocate(allocation_ticket, capacity_evidence)
        lease_receipt = port.allocator.issue_lease_binding_receipt(
            lease, allocation_ticket, capacity_evidence
        )
        lease_binding = LeaseBindingConsumerInputV1(
            receipt=lease_receipt,
            lease=lease,
            allocation_ticket=allocation_ticket,
            capacity_evidence=capacity_evidence,
        )
        current = port.ledger.append_phase(
            current,
            SpawnPhase.LEASE_RESERVED,
            expected_revision=current.ledger_revision,
            expected_fence_epoch=current.fence_epoch,
            teamlead=port.teamlead,
            lease_binding=lease_binding,
        )
        reservation = WorkerRegistryReservationIssuerV2(port.allocator).issue(
            resolution=resolution,
            current_ticket=current,
            principal_id=port.principal_id,
            lease_binding=lease_binding,
        )
    except DynamicWorkerCoordinatorDenied:
        raise
    except Exception as exc:
        raise DynamicWorkerCoordinatorDenied(
            "dynamic worker coordination denied"
        ) from exc

    attempt = _PreStartAttemptV1(current, lease_binding, reservation)
    receipt = PreStartReceiptV1(port._token, attempt)
    port._receipt_states[id(receipt)] = "active"
    try:
        object.__setattr__(
            attempt,
            "projection_receipt",
            port.projection_port.project(current, resolution, lease_binding),
        )
        current = port.ledger.append_phase(
            current,
            SpawnPhase.PROJECTED,
            expected_revision=current.ledger_revision,
            expected_fence_epoch=current.fence_epoch,
            teamlead=port.teamlead,
        )
        object.__setattr__(attempt, "ticket", current)
        try:
            home_receipt = port.home_port.commit(
                current, attempt.projection_receipt, lease_binding
            )
        except Exception as exc:
            quarantine_dynamic_worker_unknown_or_started(
                port, receipt, recovery_unknown=True
            )
            raise DynamicWorkerCoordinatorDenied("home commit outcome unknown") from exc
        if home_receipt is None:
            quarantine_dynamic_worker_unknown_or_started(
                port, receipt, recovery_unknown=True
            )
            raise DynamicWorkerCoordinatorDenied("home commit receipt denied")
        object.__setattr__(attempt, "home_receipt", home_receipt)
        current = port.ledger.append_phase(
            current,
            SpawnPhase.HOME_COMMITTED,
            expected_revision=current.ledger_revision,
            expected_fence_epoch=current.fence_epoch,
            teamlead=port.teamlead,
        )
        object.__setattr__(attempt, "ticket", current)
        current = port.ledger.record_registry_intent(
            current,
            expected_revision=current.ledger_revision,
            expected_fence_epoch=current.fence_epoch,
            teamlead=port.teamlead,
        )
        object.__setattr__(attempt, "ticket", current)
        try:
            before = port.registry_port.read_snapshot()
        except Exception as exc:
            quarantine_dynamic_worker_unknown_or_started(
                port, receipt, recovery_unknown=True
            )
            raise DynamicWorkerCoordinatorDenied(
                "registry snapshot unavailable"
            ) from exc
        if type(before) is not FleetSnapshotV2:
            quarantine_dynamic_worker_unknown_or_started(
                port, receipt, recovery_unknown=True
            )
            raise DynamicWorkerCoordinatorDenied("registry snapshot denied")
        object.__setattr__(attempt, "registry_before", before)
        operation = DynamicWorkerRegistryPlannerV2(
            port.allocator
        ).plan_dynamic_worker_principal_reserve(
            before,
            reservation,
            expected_generation=before.generation,
        )
        candidate = None
        committed = None
        try:
            with operation as candidate:
                object.__setattr__(attempt, "registry_reserved", candidate)
                committed = port.registry_port.compare_and_swap(
                    candidate, expected_generation=before.generation
                )
        except Exception as exc:
            try:
                classified = port.registry_port.read_snapshot()
            except Exception:
                quarantine_dynamic_worker_unknown_or_started(
                    port, receipt, recovery_unknown=True
                )
                raise DynamicWorkerCoordinatorDenied(
                    "registry reservation outcome unknown"
                ) from exc
            if type(classified) is not FleetSnapshotV2 or classified != candidate:
                quarantine_dynamic_worker_unknown_or_started(
                    port, receipt, recovery_unknown=True
                )
                raise DynamicWorkerCoordinatorDenied(
                    "registry reservation outcome unknown"
                ) from exc
            committed = classified
        if committed != candidate:
            try:
                classified = port.registry_port.read_snapshot()
            except Exception as exc:
                quarantine_dynamic_worker_unknown_or_started(
                    port, receipt, recovery_unknown=True
                )
                raise DynamicWorkerCoordinatorDenied(
                    "registry reservation outcome unknown"
                ) from exc
            if type(classified) is not FleetSnapshotV2 or classified != candidate:
                quarantine_dynamic_worker_unknown_or_started(
                    port, receipt, recovery_unknown=True
                )
                raise DynamicWorkerCoordinatorDenied(
                    "registry reservation outcome unknown"
                )
        current = port.ledger.append_phase(
            current,
            SpawnPhase.REGISTRY_RESERVED,
            expected_revision=current.ledger_revision,
            expected_fence_epoch=current.fence_epoch,
            teamlead=port.teamlead,
        )
        object.__setattr__(attempt, "ticket", current)
        return receipt
    except DynamicWorkerCoordinatorDenied:
        raise
    except Exception as exc:
        try:
            compensate_dynamic_worker_not_started(port, receipt)
        except Exception:
            pass
        raise DynamicWorkerCoordinatorDenied(
            "dynamic worker coordination denied"
        ) from exc


def compensate_dynamic_worker_not_started(
    port: object,
    receipt: object,
) -> dict[str, str]:
    """Compensate one exact pre-A3 reservation without CAS retry."""

    if (
        type(port) is not DynamicWorkerPreStartPortV1
        or type(receipt) is not PreStartReceiptV1
    ):
        raise DynamicWorkerCoordinatorDenied("pre-start receipt denied")
    try:
        token = object.__getattribute__(receipt, "_port_token")
        attempt = object.__getattribute__(receipt, "_attempt")
    except (AttributeError, TypeError) as exc:
        raise DynamicWorkerCoordinatorDenied("pre-start receipt denied") from exc
    if (
        token is not port._token
        or type(attempt) is not _PreStartAttemptV1
        or port._receipt_states.get(id(receipt)) != "active"
        or type(attempt.ticket) is not WorkerSpawnTicketV2
        or type(attempt.lease_binding) is not LeaseBindingConsumerInputV1
        or type(attempt.reservation) is not WorkerRegistryReservationV2
    ):
        raise DynamicWorkerCoordinatorDenied("pre-start receipt denied")
    current = port.ledger.read(attempt.ticket.request_id)
    if current is not attempt.ticket:
        raise DynamicWorkerCoordinatorDenied("pre-start receipt denied")
    port._receipt_states[id(receipt)] = "used"

    state = port.state_port.read()
    journals = tuple(
        item for item in state.failure_journals if item.ticket_id == current.ticket_id
    )
    if len(journals) > 1:
        raise DynamicWorkerCoordinatorDenied("failure journal denied")
    if not journals:
        current = port.ledger.record_failure(
            current,
            primary_failure_code=WorkerFailureCodeV1.PRE_A3_FAILURE,
            primary_failure_origin=WorkerFailureOriginV1.PRE_A3,
            compensation_status=CompensationStatusV1.REGISTRY_RELEASE_PENDING,
            expected_revision=current.ledger_revision,
            expected_fence_epoch=current.fence_epoch,
            teamlead=port.teamlead,
        )
        object.__setattr__(attempt, "ticket", current)
    elif (
        journals[0].primary_failure_code is not WorkerFailureCodeV1.PRE_A3_FAILURE
        or journals[0].primary_failure_origin is not WorkerFailureOriginV1.PRE_A3
        or journals[0].compensation_status
        is not CompensationStatusV1.REGISTRY_RELEASE_PENDING
    ):
        raise DynamicWorkerCoordinatorDenied("failure journal denied")

    if attempt.registry_reserved is not None:
        try:
            snapshot = port.registry_port.read_snapshot()
        except Exception:
            return quarantine_dynamic_worker_unknown_or_started(
                port, current, recovery_unknown=True
            )
        if type(snapshot) is not FleetSnapshotV2:
            return quarantine_dynamic_worker_unknown_or_started(
                port, current, recovery_unknown=True
            )
        if snapshot == attempt.registry_reserved:
            operation = DynamicWorkerRegistryPlannerV2(
                port.allocator
            ).plan_dynamic_worker_principal_release(
                snapshot,
                attempt.reservation,
                expected_generation=snapshot.generation,
            )
            candidate = None
            released = None
            try:
                with operation as candidate:
                    released = port.registry_port.compare_and_swap(
                        candidate, expected_generation=snapshot.generation
                    )
            except Exception:
                try:
                    classified = port.registry_port.read_snapshot()
                except Exception:
                    return quarantine_dynamic_worker_unknown_or_started(
                        port, current, recovery_unknown=True
                    )
                if type(classified) is not FleetSnapshotV2 or classified != candidate:
                    return quarantine_dynamic_worker_unknown_or_started(
                        port, current, recovery_unknown=True
                    )
                released = classified
            if released != candidate:
                try:
                    classified = port.registry_port.read_snapshot()
                except Exception:
                    return quarantine_dynamic_worker_unknown_or_started(
                        port, current, recovery_unknown=True
                    )
                if type(classified) is not FleetSnapshotV2 or classified != candidate:
                    return quarantine_dynamic_worker_unknown_or_started(
                        port, current, recovery_unknown=True
                    )
        elif attempt.registry_before is None or snapshot != attempt.registry_before:
            return quarantine_dynamic_worker_unknown_or_started(
                port, current, recovery_unknown=True
            )

    current = port.ledger.advance_compensation_status(
        current,
        compensation_status=CompensationStatusV1.REGISTRY_RELEASED,
        expected_revision=current.ledger_revision,
        expected_fence_epoch=current.fence_epoch,
        teamlead=port.teamlead,
    )
    object.__setattr__(attempt, "ticket", current)
    if attempt.home_receipt is not None:
        try:
            port.home_port.cleanup(attempt.home_receipt)
        except Exception:
            current = port.ledger.advance_compensation_status(
                current,
                compensation_status=CompensationStatusV1.HOME_RELEASE_FAILED,
                expected_revision=current.ledger_revision,
                expected_fence_epoch=current.fence_epoch,
                teamlead=port.teamlead,
            )
            object.__setattr__(attempt, "ticket", current)
            return quarantine_dynamic_worker_unknown_or_started(
                port, current, recovery_unknown=True
            )
    try:
        port.allocator.revoke(attempt.lease_binding.lease, "pre-a3-compensation")
    except Exception:
        current = port.ledger.advance_compensation_status(
            current,
            compensation_status=CompensationStatusV1.LEASE_RELEASE_FAILED,
            expected_revision=current.ledger_revision,
            expected_fence_epoch=current.fence_epoch,
            teamlead=port.teamlead,
        )
        object.__setattr__(attempt, "ticket", current)
        return quarantine_dynamic_worker_unknown_or_started(
            port, current, recovery_unknown=True
        )
    current = port.ledger.advance_compensation_status(
        current,
        compensation_status=CompensationStatusV1.COMPENSATED,
        expected_revision=current.ledger_revision,
        expected_fence_epoch=current.fence_epoch,
        teamlead=port.teamlead,
    )
    current = port.ledger.append_phase(
        current,
        SpawnPhase.ROLLED_BACK,
        expected_revision=current.ledger_revision,
        expected_fence_epoch=current.fence_epoch,
        teamlead=port.teamlead,
    )
    object.__setattr__(attempt, "ticket", current)
    return {"status": "ROLLED_BACK", "reason": "PRE_A3_COMPENSATED"}


def quarantine_dynamic_worker_unknown_or_started(
    port: object,
    receipt: object,
    *,
    recovery_unknown: bool = False,
) -> dict[str, str]:
    """Quarantine unknown or post-A3 state without destructive operations."""

    if (
        type(port) is not DynamicWorkerPreStartPortV1
        or type(recovery_unknown) is not bool
        or type(port.ledger) is not WorkerSpawnLedger
        or not isinstance(port.state_port, SpawnLedgerStatePort)
        or type(port.allocator) is not RuntimeAccountAllocator
        or type(port.allocation_port) is not _DynamicWorkerAllocationPortV1
        or type(port.projection_port) is not _DynamicWorkerProjectionPortV1
        or type(port.home_port) is not _DynamicWorkerHomePortV1
        or type(port.registry_port) is not _DynamicWorkerRegistryPortV1
        or type(port.teamlead) is not VerifiedPrincipalV2
        or port.teamlead.role is not PrincipalRole.TEAMLEADER
        or object.__getattribute__(port.ledger, "_state_port") is not port.state_port
        or object.__getattribute__(port.ledger, "_allocator") is not port.allocator
    ):
        raise DynamicWorkerCoordinatorDenied("quarantine input denied")
    if type(receipt) is PreStartReceiptV1:
        try:
            token = object.__getattribute__(receipt, "_port_token")
            attempt = object.__getattribute__(receipt, "_attempt")
        except (AttributeError, TypeError) as exc:
            raise DynamicWorkerCoordinatorDenied("pre-start receipt denied") from exc
        if (
            token is not port._token
            or type(attempt) is not _PreStartAttemptV1
            or port._receipt_states.get(id(receipt)) != "active"
        ):
            raise DynamicWorkerCoordinatorDenied("pre-start receipt denied")
        current = port.ledger.read(attempt.ticket.request_id)
        if current is not attempt.ticket:
            raise DynamicWorkerCoordinatorDenied("pre-start receipt denied")
        port._receipt_states[id(receipt)] = "used"
    elif type(receipt) is WorkerSpawnTicketV2:
        current = port.ledger.read(receipt.request_id)
        if current is not receipt:
            raise DynamicWorkerCoordinatorDenied("quarantine ticket denied")
    else:
        raise DynamicWorkerCoordinatorDenied("quarantine input denied")

    state = port.state_port.read()
    journals = tuple(
        item for item in state.failure_journals if item.ticket_id == current.ticket_id
    )
    if len(journals) > 1:
        raise DynamicWorkerCoordinatorDenied("failure journal denied")
    if not journals:
        current = port.ledger.record_failure(
            current,
            primary_failure_code=(
                WorkerFailureCodeV1.START_STATE_UNKNOWN
                if recovery_unknown
                else WorkerFailureCodeV1.A3_EXECUTION_FAILED_OR_UNKNOWN
            ),
            primary_failure_origin=(
                WorkerFailureOriginV1.RECOVERY_UNKNOWN
                if recovery_unknown
                else WorkerFailureOriginV1.A3_ENTERED
            ),
            compensation_status=CompensationStatusV1.QUARANTINED,
            expected_revision=current.ledger_revision,
            expected_fence_epoch=current.fence_epoch,
            teamlead=port.teamlead,
        )
    elif journals[0].compensation_status is not CompensationStatusV1.QUARANTINED:
        current = port.ledger.advance_compensation_status(
            current,
            compensation_status=CompensationStatusV1.QUARANTINED,
            expected_revision=current.ledger_revision,
            expected_fence_epoch=current.fence_epoch,
            teamlead=port.teamlead,
        )
    current = port.ledger.append_phase(
        current,
        SpawnPhase.QUARANTINED,
        expected_revision=current.ledger_revision,
        expected_fence_epoch=current.fence_epoch,
        teamlead=port.teamlead,
    )
    if type(receipt) is PreStartReceiptV1:
        object.__setattr__(attempt, "ticket", current)
    return {"status": "QUARANTINED", "reason": "STATE_UNKNOWN_OR_STARTED"}


__all__ = ["DynamicWorkerPreStartPortV1", "PreStartReceiptV1"]
