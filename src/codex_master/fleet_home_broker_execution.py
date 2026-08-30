"""Root-owned offline CHPB/2 provision and replacement execution composition.

This module is deliberately an adapter around the existing offline transaction,
WAL, Linux-attestation, and B2a recovery contracts.  It owns no transport and
does not introduce a second persistence state machine.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from codex_master.fleet_home_broker import (
    OfflineBrokerPlan,
    begin_offline_transaction,
    recover_offline_transaction,
)
from codex_master.fleet_home_broker_consumer import BrokerIntentResumeContext
from codex_master.fleet_home_broker_dispatch import (
    BrokerDispatchCommand,
    BrokerDispatchOperations,
)
from codex_master.fleet_home_broker_intent import BrokerIntentOperation, BrokerIntentV1
from codex_master.fleet_home_broker_linux import LinuxOperations
from codex_master.fleet_home_broker_protocol import (
    B2aRecoveryPhase,
    BrokerCheckpoint,
    BrokerObservation,
    BrokerObjectState,
    BrokerRecoveryAction,
    BrokerReply,
    BrokerResultCode,
    BrokerRegistryState,
    CHPB_PROTOCOL,
    ChpbMessageKind,
    ChpbTransactionOperation,
    PolicyBinding,
    ProvisionHomeRequest,
    ReplaceHomeRequest,
    TransactionBinding,
    TransactionStatus,
    b2a_phase_for_checkpoint,
    decide_broker_recovery,
    validate_transaction_binding,
    validate_transaction_status,
)
from codex_master.fleet_home_broker_transport import BrokerTransportResponse
from codex_master.fleet_home_broker_wal import (
    WalOperations,
    append_status,
    recover_status,
)


_INITIAL_PROVISION_OBSERVATION = BrokerObservation(
    BrokerObjectState.ABSENT, BrokerRegistryState.NOT_APPLICABLE, 0
)
_INITIAL_REPLACEMENT_OBSERVATION = BrokerObservation(
    BrokerObjectState.REPLACEMENT_ORIGINAL,
    BrokerRegistryState.NOT_APPLICABLE,
    0,
)
_MAX_DRIVE_STEPS = 2 * 256 + 16
_EXECUTION_CHECKPOINTS = {
    BrokerCheckpoint.CREATE_INTENT,
    BrokerCheckpoint.STAGING_PINNED,
    BrokerCheckpoint.POPULATE_PENDING,
    BrokerCheckpoint.PUBLISH_INTENT,
    BrokerCheckpoint.PUBLISHED,
    BrokerCheckpoint.REGISTRY_CAS_INTENT,
    BrokerCheckpoint.FINALIZE_INTENT,
    BrokerCheckpoint.COMMITTED,
    BrokerCheckpoint.BLOCKED_DRIFT,
    BrokerCheckpoint.REPLACEMENT_PREPARE_INTENT,
    BrokerCheckpoint.REPLACEMENT_PREPARED,
    BrokerCheckpoint.SWITCH_INTENT,
    BrokerCheckpoint.SWITCHED,
}
_SUPPORTED_OPERATIONS = frozenset(
    (ChpbTransactionOperation.PROVISION, ChpbTransactionOperation.REPLACE)
)


class RootBrokerExecutionOperations(Protocol):
    """Injected root-owned effects selected by the existing B2a recovery rules."""

    def new_transaction_id(self) -> str: ...

    def observe(self, plan: OfflineBrokerPlan) -> BrokerObservation: ...

    def create_staging(self, plan: OfflineBrokerPlan) -> None: ...

    def populate_next(self, plan: OfflineBrokerPlan) -> None: ...

    def publish_home(self, plan: OfflineBrokerPlan) -> None: ...

    def prepare_replacement(self, plan: OfflineBrokerPlan) -> None: ...

    def switch_replacement(
        self, plan: OfflineBrokerPlan, binding: TransactionBinding
    ) -> None: ...

    def cas_registry(
        self, plan: OfflineBrokerPlan, binding: TransactionBinding
    ) -> None: ...

    def close(self, fd: int) -> None: ...


# A2's public protocol name remains an alias for compatibility while A3a adds
# the replacement-only primitives to the same single injection boundary.
RootBrokerProvisionOperations = RootBrokerExecutionOperations


@dataclass(frozen=True, slots=True)
class _FixedTransactionOperations:
    """Keep broker bootstrap bound to the caller's pre-attested transaction."""

    operations: RootBrokerExecutionOperations
    transaction_id: str

    def new_transaction_id(self) -> str:
        # The intent/request transaction ID is the durable execution identity.
        # Calling a fresh-id generator here would make an interrupted intent
        # resumable under a second transaction.
        return self.transaction_id

    def observe(self, plan: OfflineBrokerPlan) -> BrokerObservation:
        return self.operations.observe(plan)


class RootBrokerExecutionComposition(BrokerDispatchOperations):
    """The one offline provision/replacement implementation behind dispatch."""

    def __init__(
        self,
        operations: RootBrokerExecutionOperations,
        linux_operations: LinuxOperations,
        wal_operations: WalOperations,
        *,
        peer_pid: int,
    ) -> None:
        self._operations = operations
        self._linux_operations = linux_operations
        self._wal_operations = wal_operations
        self._peer_pid = peer_pid

    def close(self, fd: int) -> None:
        if type(fd) is not int or fd < 0:
            return
        try:
            self._operations.close(fd)
        except Exception:
            pass

    def execute(self, command: BrokerDispatchCommand) -> BrokerTransportResponse:
        request_id = self._request_id(getattr(command, "request", None))
        try:
            request = command.request
            plan = command.plan
            if (
                type(command) is not BrokerDispatchCommand
                or type(plan) is not OfflineBrokerPlan
                or type(request)
                is not {
                    ChpbTransactionOperation.PROVISION: ProvisionHomeRequest,
                    ChpbTransactionOperation.REPLACE: ReplaceHomeRequest,
                }.get(plan.operation)
                or plan.operation not in _SUPPORTED_OPERATIONS
                or not self._valid_request_id(request.request_id)
                or command.principal != plan.expected_principal
                or request.binding != self._binding_for(plan, request.transaction_id)
            ):
                return self._unbound_failure(request_id)
            return self._execute_new(plan, request.transaction_id, request_id)
        except Exception:
            return self._unbound_failure(request_id)

    def execute_intent(
        self, intent: BrokerIntentV1, plan: OfflineBrokerPlan
    ) -> BrokerTransportResponse:
        request_id = self._request_id(intent)
        if not self._plan_matches_intent(plan, intent):
            return self._blocked(plan, self._transaction_id(intent), request_id, None)
        return self._execute_new(plan, intent.transaction_id, request_id)

    def resume_intent(
        self,
        intent: BrokerIntentV1,
        plan: OfflineBrokerPlan,
        context: BrokerIntentResumeContext,
    ) -> BrokerTransportResponse:
        request_id = self._request_id(intent)
        transaction_id = self._transaction_id(intent)
        if (
            not self._plan_matches_intent(plan, intent)
            or type(context) is not BrokerIntentResumeContext
            or context.transaction_id != transaction_id
            or not self._is_initial_observation(
                plan.operation, context.initial_observation
            )
        ):
            return self._blocked(plan, transaction_id, request_id, None)

        adapter = _FixedTransactionOperations(self._operations, transaction_id)
        try:
            recovered = recover_offline_transaction(
                plan,
                self._peer_pid,
                adapter,
                self._linux_operations,
                self._wal_operations,
            )
            status = recovered.status
        except Exception:
            status = None
        if status is None:
            status = self._begin_empty_wal_recovery(plan, transaction_id)
        if status is None:
            status = self._late_recovery_status(plan, transaction_id)
        if not self._matches(plan, transaction_id, status):
            return self._blocked(plan, transaction_id, request_id, None)
        return self._drive(plan, request_id, status)

    def _begin_empty_wal_recovery(
        self, plan: OfflineBrokerPlan, transaction_id: str
    ) -> TransactionStatus | None:
        """Re-create only an attestably untouched first record with its fixed ID."""

        try:
            records = self._wal_operations.read_all()
            if type(records) is not tuple or records:
                return None
            started = begin_offline_transaction(
                plan,
                self._peer_pid,
                _FixedTransactionOperations(self._operations, transaction_id),
                self._linux_operations,
                self._wal_operations,
            )
            return started.status
        except Exception:
            return None

    def _execute_new(
        self, plan: OfflineBrokerPlan, transaction_id: str, request_id: str
    ) -> BrokerTransportResponse:
        if not self._valid_transaction_id(transaction_id):
            return self._blocked(plan, transaction_id, request_id, None)
        adapter = _FixedTransactionOperations(self._operations, transaction_id)
        try:
            started = begin_offline_transaction(
                plan,
                self._peer_pid,
                adapter,
                self._linux_operations,
                self._wal_operations,
            )
            status = started.status
        except Exception:
            status = None
        if not self._matches(plan, transaction_id, status):
            return self._blocked(plan, transaction_id, request_id, None)
        return self._drive(plan, request_id, status)

    def _drive(
        self,
        plan: OfflineBrokerPlan,
        request_id: str,
        status: TransactionStatus,
    ) -> BrokerTransportResponse:
        for _ in range(_MAX_DRIVE_STEPS):
            try:
                observation = self._operations.observe(plan)
                if type(observation) is not BrokerObservation:
                    raise ValueError("invalid observation")
                decision = decide_broker_recovery(status, observation)
                if decision.action is BrokerRecoveryAction.RETURN_COMMITTED:
                    return self._reply(request_id, BrokerResultCode.COMMITTED, status)
                if decision.action is BrokerRecoveryAction.RETURN_BLOCKED:
                    return self._blocked(
                        plan,
                        status.binding.transaction_id,
                        request_id,
                        status,
                        observation,
                    )
                if decision.action is BrokerRecoveryAction.PERSIST_CHECKPOINT:
                    status = self._persist(status, decision, observation)
                    continue
                if decision.action is BrokerRecoveryAction.CREATE_STAGING:
                    self._operations.create_staging(plan)
                    continue
                if decision.action is BrokerRecoveryAction.POPULATE_NEXT:
                    self._operations.populate_next(plan)
                    continue
                if decision.action is BrokerRecoveryAction.PUBLISH_HOME:
                    self._operations.publish_home(plan)
                    continue
                if decision.action is BrokerRecoveryAction.PREPARE_REPLACEMENT:
                    self._operations.prepare_replacement(plan)
                    continue
                if decision.action is BrokerRecoveryAction.SWITCH_REPLACEMENT:
                    self._operations.switch_replacement(plan, status.binding)
                    continue
                if decision.action is BrokerRecoveryAction.CAS_REGISTRY:
                    self._operations.cas_registry(plan, status.binding)
                    continue
                raise ValueError("unsupported provision recovery action")
            except Exception:
                return self._blocked(
                    plan, status.binding.transaction_id, request_id, status
                )
        return self._blocked(plan, status.binding.transaction_id, request_id, status)

    def _persist(
        self,
        status: TransactionStatus,
        decision: object,
        observation: BrokerObservation,
    ) -> TransactionStatus:
        target = getattr(decision, "next_checkpoint", None)
        if type(target) is not BrokerCheckpoint:
            raise ValueError("missing checkpoint")
        terminal = (
            BrokerResultCode.COMMITTED if target is BrokerCheckpoint.COMMITTED else None
        )
        next_status = TransactionStatus(
            status.binding,
            b2a_phase_for_checkpoint(target),
            target,
            observation,
            status.population_total,
            terminal,
        )
        validate_transaction_status(next_status)
        append_status(self._wal_operations, next_status)
        return next_status

    def _late_recovery_status(
        self, plan: OfflineBrokerPlan, transaction_id: str
    ) -> TransactionStatus | None:
        """Permit the existing recovery gate to hand off its late provision states."""

        try:
            observation = self._operations.observe(plan)
            if type(observation) is not BrokerObservation:
                return None
            recovered = recover_status(self._wal_operations, observation)
            status = recovered.status
            if not self._matches(plan, transaction_id, status):
                return None
            if status.checkpoint not in _EXECUTION_CHECKPOINTS:
                return None
            if recovered.decision.action is BrokerRecoveryAction.RETURN_BLOCKED:
                return None
            if (
                status.checkpoint is BrokerCheckpoint.REGISTRY_CAS_INTENT
                and recovered.decision.action is BrokerRecoveryAction.CAS_REGISTRY
            ):
                # A prior CAS may have taken effect despite its caller failing
                # before a durable terminal outcome was written.  No retry is
                # safe while the attested registry remains OLD.
                return None
            return status
        except Exception:
            return None

    def _blocked(
        self,
        plan: object,
        transaction_id: str,
        request_id: str,
        previous: TransactionStatus | None,
        observation: BrokerObservation | None = None,
    ) -> BrokerTransportResponse:
        status = previous
        if status is not None:
            observed = (
                observation
                if type(observation) is BrokerObservation
                else status.observation
            )
            # A failed fsync can report after append() made the record visible.
            # Re-read before terminalizing so an old in-memory checkpoint can
            # never be appended behind the newer durable status.
            try:
                recovered = recover_status(self._wal_operations, observed).status
                if self._matches(plan, status.binding.transaction_id, recovered):
                    status = recovered
                    observed = status.observation
            except Exception:
                pass
            status = TransactionStatus(
                status.binding,
                B2aRecoveryPhase.BLOCKED,
                BrokerCheckpoint.BLOCKED_DRIFT,
                observed,
                status.population_total,
                BrokerResultCode.BLOCKED_DRIFT,
            )
            try:
                append_status(self._wal_operations, status)
            except Exception:
                pass
            return self._reply(request_id, BrokerResultCode.BLOCKED_DRIFT, status)
        try:
            binding = self._binding_for(plan, transaction_id)
            total = plan.population_total
            initial_observation = self._initial_observation(plan.operation)
            if initial_observation is None:
                raise ValueError("unsupported operation")
            status = TransactionStatus(
                binding,
                B2aRecoveryPhase.BLOCKED,
                BrokerCheckpoint.BLOCKED_DRIFT,
                initial_observation,
                total,
                BrokerResultCode.BLOCKED_DRIFT,
            )
            validate_transaction_status(status)
            return self._reply(request_id, BrokerResultCode.BLOCKED_DRIFT, status)
        except Exception:
            return self._unbound_failure(request_id)

    @staticmethod
    def _reply(
        request_id: str, result: BrokerResultCode, status: TransactionStatus
    ) -> BrokerTransportResponse:
        return BrokerTransportResponse(
            BrokerReply(
                CHPB_PROTOCOL, ChpbMessageKind.REPLY, request_id, result, status, None
            ),
            (),
        )

    @staticmethod
    def _unbound_failure(request_id: str) -> BrokerTransportResponse:
        return BrokerTransportResponse(
            BrokerReply(
                CHPB_PROTOCOL,
                ChpbMessageKind.REPLY,
                request_id,
                BrokerResultCode.INTERNAL_ERROR,
                None,
                None,
            ),
            (),
        )

    @staticmethod
    def _request_id(value: object) -> str:
        candidate = getattr(value, "request_id", None)
        return (
            candidate
            if (
                type(candidate) is str
                and len(candidate) == 32
                and all(character in "0123456789abcdef" for character in candidate)
            )
            else "0" * 32
        )

    @staticmethod
    def _transaction_id(value: object) -> str:
        candidate = getattr(value, "transaction_id", None)
        return candidate if type(candidate) is str else ""

    @staticmethod
    def _valid_transaction_id(transaction_id: object) -> bool:
        return (
            type(transaction_id) is str
            and len(transaction_id) == 32
            and all(character in "0123456789abcdef" for character in transaction_id)
        )

    @staticmethod
    def _valid_request_id(request_id: object) -> bool:
        return RootBrokerExecutionComposition._valid_transaction_id(request_id)

    @staticmethod
    def _initial_observation(operation: object) -> BrokerObservation | None:
        return {
            ChpbTransactionOperation.PROVISION: _INITIAL_PROVISION_OBSERVATION,
            ChpbTransactionOperation.REPLACE: _INITIAL_REPLACEMENT_OBSERVATION,
        }.get(operation)

    @classmethod
    def _is_initial_observation(cls, operation: object, value: object) -> bool:
        expected = cls._initial_observation(operation)
        return (
            type(value) is BrokerObservation
            and expected is not None
            and value.object_state is expected.object_state
            and value.registry_state is expected.registry_state
            and type(value.population_index) is int
            and value.population_index == 0
        )

    @staticmethod
    def _binding_for(plan: object, transaction_id: str) -> TransactionBinding:
        if type(plan) is not OfflineBrokerPlan:
            raise ValueError("invalid plan")
        binding = TransactionBinding(
            plan.operation,
            transaction_id,
            plan.store_uuid,
            plan.expected_principal,
            PolicyBinding(
                plan.identity.policy_generation, plan.identity.projection_digest
            ),
        )
        return validate_transaction_binding(binding)

    @classmethod
    def _matches(
        cls,
        plan: object,
        transaction_id: str,
        status: object,
    ) -> bool:
        if type(status) is not TransactionStatus:
            return False
        try:
            validate_transaction_status(status)
            return status.binding == cls._binding_for(plan, transaction_id) and (
                status.population_total == plan.population_total
            )
        except Exception:
            return False

    @staticmethod
    def _plan_matches_intent(plan: object, intent: object) -> bool:
        if type(plan) is not OfflineBrokerPlan or type(intent) is not BrokerIntentV1:
            return False
        try:
            return (
                plan.operation is ChpbTransactionOperation(intent.operation.value)
                and plan.operation in _SUPPORTED_OPERATIONS
                and plan.store_uuid == intent.store_uuid
                and plan.expected_principal.agent_id == intent.agent_id
                and plan.expected_principal.manifest_generation
                == intent.manifest_generation
                and plan.expected_principal.unit_generation == intent.unit_generation
                and plan.expected_principal.mcs_pair == intent.mcs_pair
                and plan.expected_principal.fencing_epoch == intent.fencing_epoch
                and plan.identity.agent_id == intent.agent_id
                and plan.identity.manifest_generation == intent.manifest_generation
                and plan.identity.mcs_pair == intent.mcs_pair
                and plan.identity.slot_snapshot == intent.slot_id
                and plan.identity.policy_generation == intent.policy_generation
                and plan.identity.projection_digest == intent.projection_digest
                and plan.identity.fencing_epoch == intent.fencing_epoch
                and type(intent.operation) is BrokerIntentOperation
            )
        except Exception:
            return False


__all__ = (
    "RootBrokerExecutionComposition",
    "RootBrokerExecutionOperations",
    "RootBrokerProvisionOperations",
)
