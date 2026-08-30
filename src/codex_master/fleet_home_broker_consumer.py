"""Single-use, offline consumer for root-owned broker intents."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from codex_master.fleet_home_broker import OfflineBrokerPlan
from codex_master.fleet_home_broker_dispatch import BrokerDispatchOperations
from codex_master.fleet_home_broker_intent import BrokerIntentV1
from codex_master.fleet_home_broker_intent_store import (
    BrokerIntentStoreOperations,
    claim_broker_intent,
    recover_broker_intent,
)
from codex_master.fleet_home_broker_protocol import (
    BrokerObservation,
    BrokerObjectState,
    BrokerReply,
    BrokerRegistryState,
    BrokerResultCode,
    ChpbTransactionOperation,
    validate_chpb_message,
)
from codex_master.fleet_home_broker_transport import BrokerTransportResponse


class BrokerIntentConsumeCode(str, Enum):
    """Stable, value-free outcomes for one claimed broker intent."""

    EMPTY = "empty"
    SUCCEEDED = "succeeded"
    RESOLVER_DRIFT = "resolver_drift"
    RESOLUTION_FAILED = "resolution_failed"
    EXECUTION_FAILED = "execution_failed"
    BLOCKED_DRIFT = "blocked_drift"
    TERMINAL_WRITE_FAILED = "terminal_write_failed"
    INVALID_RESULT = "invalid_result"


class BrokerIntentConsumerError(ValueError):
    """Stable, value-free consumer failure."""

    __slots__ = ("code",)

    def __init__(self, code: BrokerIntentConsumeCode) -> None:
        if type(code) is not BrokerIntentConsumeCode:
            code = BrokerIntentConsumeCode.INVALID_RESULT
        self.code = code
        super().__init__(code.value)


@dataclass(frozen=True, slots=True)
class BrokerIntentConsumeResult:
    code: BrokerIntentConsumeCode

    def __post_init__(self) -> None:
        if type(self.code) is not BrokerIntentConsumeCode:
            raise BrokerIntentConsumerError(BrokerIntentConsumeCode.INVALID_RESULT)


@dataclass(frozen=True, slots=True)
class BrokerIntentResumeContext:
    """The exact fresh-state fact a recovery implementation must attest."""

    transaction_id: str
    initial_observation: BrokerObservation

    def __post_init__(self) -> None:
        if (
            type(self.transaction_id) is not str
            or type(self.initial_observation) is not BrokerObservation
        ):
            raise BrokerIntentConsumerError(BrokerIntentConsumeCode.INVALID_RESULT)


class BrokerIntentResolver(Protocol):
    def resolve_plan(self, intent: BrokerIntentV1) -> OfflineBrokerPlan: ...


class BrokerExecutionComposition(BrokerDispatchOperations, Protocol):
    def execute_intent(
        self, intent: BrokerIntentV1, plan: OfflineBrokerPlan
    ) -> BrokerTransportResponse: ...

    def resume_intent(
        self,
        intent: BrokerIntentV1,
        plan: OfflineBrokerPlan,
        context: BrokerIntentResumeContext,
    ) -> BrokerTransportResponse: ...


_TERMINAL_PAYLOADS = {
    BrokerIntentConsumeCode.SUCCEEDED: b'{"result":"succeeded"}\n',
    BrokerIntentConsumeCode.RESOLVER_DRIFT: b'{"result":"resolver_drift"}\n',
    BrokerIntentConsumeCode.RESOLUTION_FAILED: b'{"result":"resolution_failed"}\n',
    BrokerIntentConsumeCode.EXECUTION_FAILED: b'{"result":"execution_failed"}\n',
    BrokerIntentConsumeCode.BLOCKED_DRIFT: b'{"result":"blocked_drift"}\n',
}


def _plan_matches_intent(plan: object, intent: BrokerIntentV1) -> bool:
    if type(plan) is not OfflineBrokerPlan:
        return False
    try:
        return (
            plan.operation.value == intent.operation.value
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
        )
    except Exception:
        return False


def _mark_terminal(
    store: BrokerIntentStoreOperations, claim_name: str, code: BrokerIntentConsumeCode
) -> None:
    terminal_failed = False
    try:
        result = store.mark_terminal(claim_name, _TERMINAL_PAYLOADS[code])
        if result is not None:
            terminal_failed = True
    except Exception:
        terminal_failed = True
    if terminal_failed:
        raise BrokerIntentConsumerError(BrokerIntentConsumeCode.TERMINAL_WRITE_FAILED)


def _execution_result(
    response: object, intent: BrokerIntentV1, *, recovered: bool
) -> BrokerIntentConsumeCode | None:
    if type(response) is not BrokerTransportResponse or type(response.fds) is not tuple:
        return None
    if response.fds:
        return None
    try:
        reply = validate_chpb_message(response.reply)
        if type(reply) is not BrokerReply or reply.request_id != intent.request_id:
            return None
        status = reply.transaction
        if status is None or status.binding.transaction_id != intent.transaction_id:
            return None
        binding = status.binding
        principal = binding.principal
        policy = binding.policy
        if not (
            binding.operation is ChpbTransactionOperation(intent.operation.value)
            and binding.store_uuid == intent.store_uuid
            and principal.agent_id == intent.agent_id
            and principal.manifest_generation == intent.manifest_generation
            and principal.unit_generation == intent.unit_generation
            and principal.mcs_pair == intent.mcs_pair
            and principal.fencing_epoch == intent.fencing_epoch
            and policy.policy_generation == intent.policy_generation
            and policy.projection_digest == intent.projection_digest
        ):
            return None
        if (
            reply.result is BrokerResultCode.COMMITTED
            and status.terminal_result is BrokerResultCode.COMMITTED
        ):
            return BrokerIntentConsumeCode.SUCCEEDED
        if (
            recovered
            and reply.result is BrokerResultCode.BLOCKED_DRIFT
            and status.terminal_result is BrokerResultCode.BLOCKED_DRIFT
        ):
            return BrokerIntentConsumeCode.BLOCKED_DRIFT
        return None
    except Exception:
        return None


def _response_fds(response: object) -> tuple[int, ...]:
    try:
        fds = response.fds
        if type(fds) not in (tuple, list, set, frozenset):
            return ()
        valid = []
        for fd in fds:
            if type(fd) is int and fd >= 0 and fd not in valid:
                valid.append(fd)
        if type(fds) in (set, frozenset):
            valid.sort()
        return tuple(valid)
    except Exception:
        return ()


def _close_response_fds(
    execution: BrokerExecutionComposition, response: object
) -> None:
    for fd in _response_fds(response):
        try:
            execution.close(fd)
        except Exception:
            pass


def _resume_context(intent: BrokerIntentV1) -> BrokerIntentResumeContext:
    observations = {
        ChpbTransactionOperation.PROVISION: BrokerObservation(
            BrokerObjectState.ABSENT,
            BrokerRegistryState.NOT_APPLICABLE,
            0,
        ),
        ChpbTransactionOperation.REPLACE: BrokerObservation(
            BrokerObjectState.REPLACEMENT_ORIGINAL,
            BrokerRegistryState.NOT_APPLICABLE,
            0,
        ),
        ChpbTransactionOperation.DEPROVISION: BrokerObservation(
            BrokerObjectState.FINAL_COMPLETE,
            BrokerRegistryState.NOT_APPLICABLE,
            0,
        ),
    }
    try:
        operation = ChpbTransactionOperation(intent.operation.value)
        return BrokerIntentResumeContext(intent.transaction_id, observations[operation])
    except Exception:
        raise BrokerIntentConsumerError(
            BrokerIntentConsumeCode.INVALID_RESULT
        ) from None


def _release_claim(store: BrokerIntentStoreOperations, claim_name: str) -> None:
    try:
        store.release_claim(claim_name)
    except Exception:
        pass


def consume_one_broker_intent(
    store: BrokerIntentStoreOperations,
    resolver: BrokerIntentResolver,
    execution: BrokerExecutionComposition,
    *,
    now_unix_ms: int,
) -> BrokerIntentConsumeResult:
    """Claim once, execute once, and retain a terminal record."""

    claimed = claim_broker_intent(store, now_unix_ms=now_unix_ms)
    if claimed is None:
        claimed = recover_broker_intent(store, now_unix_ms=now_unix_ms)
    if claimed is None:
        return BrokerIntentConsumeResult(BrokerIntentConsumeCode.EMPTY)
    try:
        resolution_failed = False
        try:
            plan = resolver.resolve_plan(claimed.intent)
        except Exception:
            resolution_failed = True
            plan = None
        if resolution_failed:
            _mark_terminal(
                store, claimed.claim_name, BrokerIntentConsumeCode.RESOLUTION_FAILED
            )
            return BrokerIntentConsumeResult(BrokerIntentConsumeCode.RESOLUTION_FAILED)
        if not _plan_matches_intent(plan, claimed.intent):
            _mark_terminal(
                store, claimed.claim_name, BrokerIntentConsumeCode.RESOLVER_DRIFT
            )
            return BrokerIntentConsumeResult(BrokerIntentConsumeCode.RESOLVER_DRIFT)
        execution_failed = False
        response = None
        outcome = None
        try:
            if claimed.recovered:
                response = execution.resume_intent(
                    claimed.intent, plan, _resume_context(claimed.intent)
                )
            else:
                response = execution.execute_intent(claimed.intent, plan)
            outcome = _execution_result(
                response, claimed.intent, recovered=claimed.recovered
            )
            if outcome is None:
                execution_failed = True
        except Exception:
            execution_failed = True
        if execution_failed:
            _close_response_fds(execution, response)
            _mark_terminal(
                store, claimed.claim_name, BrokerIntentConsumeCode.EXECUTION_FAILED
            )
            return BrokerIntentConsumeResult(BrokerIntentConsumeCode.EXECUTION_FAILED)
        assert outcome is not None
        _mark_terminal(store, claimed.claim_name, outcome)
        return BrokerIntentConsumeResult(outcome)
    finally:
        _release_claim(store, claimed.claim_name)


__all__ = (
    "BrokerExecutionComposition",
    "BrokerIntentConsumeCode",
    "BrokerIntentConsumeResult",
    "BrokerIntentConsumerError",
    "BrokerIntentResumeContext",
    "BrokerIntentResolver",
    "consume_one_broker_intent",
)
