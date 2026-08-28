"""Offline, injected CHPB/2 broker transaction boundary."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .fleet_home_broker_identity import BrokerIdentity, ImportClosure
from .fleet_home_broker_linux import LinuxOperations, attest_peer_principal
from .fleet_home_broker_protocol import (
    B2aRecoveryPhase,
    BrokerCheckpoint,
    BrokerObservation,
    BrokerObjectState,
    BrokerRecoveryAction,
    BrokerRegistryState,
    BrokerResultCode,
    ChpbTransactionOperation,
    MAX_CHPB_POPULATION_ENTRIES,
    PolicyBinding,
    PrincipalBinding,
    RecoveryDecision,
    TransactionBinding,
    TransactionStatus,
    b2a_phase_for_checkpoint,
    decide_broker_recovery,
    validate_principal_binding,
    validate_transaction_binding,
    validate_transaction_status,
)
from .fleet_home_broker_wal import WalOperations, append_status, recover_status


class OfflineBrokerError(ValueError):
    """Raised when an offline broker plan or generated binding is invalid."""

    __slots__ = ()


@dataclass(frozen=True, slots=True)
class OfflineBrokerPlan:
    identity: BrokerIdentity
    import_closure: ImportClosure
    expected_principal: PrincipalBinding
    operation: ChpbTransactionOperation
    store_uuid: str
    population_total: int


@dataclass(frozen=True, slots=True)
class OfflineBrokerStep:
    status: TransactionStatus | None
    decision: RecoveryDecision


class OfflineBrokerOperations(Protocol):
    def new_transaction_id(self) -> str: ...

    def observe(self, plan: OfflineBrokerPlan) -> BrokerObservation: ...


def _blocked_decision() -> RecoveryDecision:
    return RecoveryDecision(
        BrokerRecoveryAction.RETURN_BLOCKED,
        B2aRecoveryPhase.BLOCKED,
        BrokerCheckpoint.BLOCKED_DRIFT,
        BrokerResultCode.BLOCKED_DRIFT,
    )


def _blocked_step() -> OfflineBrokerStep:
    return OfflineBrokerStep(None, _blocked_decision())


def _invalid(message: str, cause: Exception | None = None) -> None:
    if cause is None:
        raise OfflineBrokerError(message)
    raise OfflineBrokerError(message) from cause


def _validate_plan(plan: OfflineBrokerPlan) -> PolicyBinding:
    if type(plan) is not OfflineBrokerPlan:
        _invalid("offline broker plan type is invalid")
    if type(plan.identity) is not BrokerIdentity:
        _invalid("offline broker identity type is invalid")
    if type(plan.import_closure) is not ImportClosure:
        _invalid("offline broker import closure type is invalid")
    if type(plan.expected_principal) is not PrincipalBinding:
        _invalid("offline broker principal type is invalid")
    if type(plan.operation) is not ChpbTransactionOperation:
        _invalid("offline broker operation type is invalid")

    try:
        identity = BrokerIdentity(
            plan.identity.agent_id,
            plan.identity.manifest_generation,
            plan.identity.mcs_pair,
            plan.identity.slot_snapshot,
            plan.identity.policy_generation,
            plan.identity.projection_digest,
            plan.identity.executable_fingerprint,
            plan.identity.fencing_epoch,
        )
        closure = ImportClosure(plan.import_closure.entries)
        validate_principal_binding(plan.expected_principal)
    except Exception as exc:
        _invalid("offline broker plan is invalid", exc)

    if identity.executable_fingerprint != closure.digest():
        _invalid("executable fingerprint is not bound to import closure")
    if (
        identity.agent_id != plan.expected_principal.agent_id
        or identity.manifest_generation != plan.expected_principal.manifest_generation
        or identity.mcs_pair != plan.expected_principal.mcs_pair
        or identity.fencing_epoch != plan.expected_principal.fencing_epoch
    ):
        _invalid("identity and expected principal are not bound")

    policy = PolicyBinding(identity.policy_generation, identity.projection_digest)
    try:
        validate_transaction_binding(
            TransactionBinding(
                plan.operation,
                "0" * 32,
                plan.store_uuid,
                plan.expected_principal,
                policy,
            )
        )
    except Exception as exc:
        _invalid("offline broker store or binding is invalid", exc)

    if (
        type(plan.population_total) is not int
        or not 1 <= plan.population_total <= MAX_CHPB_POPULATION_ENTRIES
    ):
        _invalid("offline broker population total is invalid")
    return policy


def _validate_peer_pid(peer_pid: int) -> None:
    if type(peer_pid) is not int or peer_pid <= 0:
        _invalid("peer pid is invalid")


def _new_binding(
    plan: OfflineBrokerPlan, policy: PolicyBinding, transaction_id: str
) -> TransactionBinding:
    binding = TransactionBinding(
        plan.operation,
        transaction_id,
        plan.store_uuid,
        plan.expected_principal,
        policy,
    )
    try:
        validate_transaction_binding(binding)
    except Exception as exc:
        _invalid("broker-generated transaction id or binding is invalid", exc)
    return binding


def _initial_observation(operation: ChpbTransactionOperation) -> BrokerObservation:
    if operation is ChpbTransactionOperation.PROVISION:
        return BrokerObservation(
            BrokerObjectState.ABSENT,
            BrokerRegistryState.NOT_APPLICABLE,
            0,
        )
    if operation is ChpbTransactionOperation.REPLACE:
        return BrokerObservation(
            BrokerObjectState.REPLACEMENT_ORIGINAL,
            BrokerRegistryState.NOT_APPLICABLE,
            0,
        )
    return BrokerObservation(
        BrokerObjectState.FINAL_COMPLETE,
        BrokerRegistryState.NOT_APPLICABLE,
        0,
    )


def _initial_checkpoint(operation: ChpbTransactionOperation) -> BrokerCheckpoint:
    if operation is ChpbTransactionOperation.PROVISION:
        return BrokerCheckpoint.CREATE_INTENT
    if operation is ChpbTransactionOperation.REPLACE:
        return BrokerCheckpoint.REPLACEMENT_PREPARE_INTENT
    return BrokerCheckpoint.DEPROVISION_INTENT


def _initial_status(
    plan: OfflineBrokerPlan,
    policy: PolicyBinding,
    transaction_id: str,
    observation: BrokerObservation,
) -> TransactionStatus:
    checkpoint = _initial_checkpoint(plan.operation)
    status = TransactionStatus(
        _new_binding(plan, policy, transaction_id),
        b2a_phase_for_checkpoint(checkpoint),
        checkpoint,
        observation,
        plan.population_total,
        None,
    )
    try:
        validate_transaction_status(status)
    except Exception as exc:
        _invalid("offline broker initial status is invalid", exc)
    return status


def _status_matches_plan(
    plan: OfflineBrokerPlan, policy: PolicyBinding, status: TransactionStatus
) -> bool:
    try:
        validate_transaction_status(status)
    except Exception:
        return False
    return (
        status.binding.operation is plan.operation
        and status.binding.store_uuid == plan.store_uuid
        and status.binding.principal == plan.expected_principal
        and status.binding.policy == policy
        and status.population_total == plan.population_total
    )


def _registry_or_terminal_blocked(
    status: TransactionStatus, decision: RecoveryDecision
) -> bool:
    if decision.action is BrokerRecoveryAction.CAS_REGISTRY:
        return True
    if decision.next_checkpoint in {
        BrokerCheckpoint.REGISTRY_CAS_INTENT,
        BrokerCheckpoint.FINALIZE_INTENT,
    }:
        return True
    if status.checkpoint in {
        BrokerCheckpoint.REGISTRY_CAS_INTENT,
        BrokerCheckpoint.FINALIZE_INTENT,
    }:
        return True
    return (
        status.binding.operation
        in (ChpbTransactionOperation.PROVISION, ChpbTransactionOperation.REPLACE)
        and status.checkpoint is BrokerCheckpoint.COMMITTED
    )


def begin_offline_transaction(
    plan: OfflineBrokerPlan,
    peer_pid: int,
    operations: OfflineBrokerOperations,
    linux_operations: LinuxOperations,
    wal_operations: WalOperations,
) -> OfflineBrokerStep:
    policy = _validate_plan(plan)
    _validate_peer_pid(peer_pid)

    try:
        transaction_id = operations.new_transaction_id()
    except Exception as exc:
        _invalid("broker transaction id generation failed", exc)
    _new_binding(plan, policy, transaction_id)

    try:
        attest_peer_principal(linux_operations, peer_pid, plan.expected_principal)
        observation = operations.observe(plan)
    except Exception:
        return _blocked_step()

    if type(observation) is not BrokerObservation:
        return _blocked_step()
    if observation != _initial_observation(plan.operation):
        return _blocked_step()

    status = _initial_status(plan, policy, transaction_id, observation)
    try:
        append_status(wal_operations, status)
    except Exception:
        return _blocked_step()
    decision = decide_broker_recovery(status, observation)
    if decision.action is BrokerRecoveryAction.RETURN_BLOCKED:
        return _blocked_step()
    return OfflineBrokerStep(status, decision)


def recover_offline_transaction(
    plan: OfflineBrokerPlan,
    peer_pid: int,
    operations: OfflineBrokerOperations,
    linux_operations: LinuxOperations,
    wal_operations: WalOperations,
) -> OfflineBrokerStep:
    policy = _validate_plan(plan)
    _validate_peer_pid(peer_pid)

    try:
        attest_peer_principal(linux_operations, peer_pid, plan.expected_principal)
        observation = operations.observe(plan)
    except Exception:
        return _blocked_step()
    if type(observation) is not BrokerObservation:
        return _blocked_step()

    recovery = recover_status(wal_operations, observation)
    if recovery.status is None:
        return _blocked_step()
    if not _status_matches_plan(plan, policy, recovery.status):
        return _blocked_step()
    if recovery.decision.action is BrokerRecoveryAction.RETURN_BLOCKED:
        return _blocked_step()
    if _registry_or_terminal_blocked(recovery.status, recovery.decision):
        return _blocked_step()
    return OfflineBrokerStep(recovery.status, recovery.decision)


__all__ = [
    "OfflineBrokerError",
    "OfflineBrokerOperations",
    "OfflineBrokerPlan",
    "OfflineBrokerStep",
    "begin_offline_transaction",
    "recover_offline_transaction",
]
