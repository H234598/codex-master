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
)
from codex_master.fleet_home_broker_protocol import validate_chpb_message
from codex_master.fleet_home_broker_transport import BrokerTransportResponse


class BrokerIntentConsumeCode(str, Enum):
    """Stable, value-free outcomes for one claimed broker intent."""

    EMPTY = "empty"
    SUCCEEDED = "succeeded"
    RESOLVER_DRIFT = "resolver_drift"
    RESOLUTION_FAILED = "resolution_failed"
    EXECUTION_FAILED = "execution_failed"
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


class BrokerIntentResolver(Protocol):
    def resolve_plan(self, intent: BrokerIntentV1) -> OfflineBrokerPlan: ...


class BrokerExecutionComposition(BrokerDispatchOperations, Protocol):
    def execute_intent(
        self, intent: BrokerIntentV1, plan: OfflineBrokerPlan
    ) -> BrokerTransportResponse: ...


_TERMINAL_PAYLOADS = {
    BrokerIntentConsumeCode.SUCCEEDED: b'{"result":"succeeded"}\n',
    BrokerIntentConsumeCode.RESOLVER_DRIFT: b'{"result":"resolver_drift"}\n',
    BrokerIntentConsumeCode.RESOLUTION_FAILED: b'{"result":"resolution_failed"}\n',
    BrokerIntentConsumeCode.EXECUTION_FAILED: b'{"result":"execution_failed"}\n',
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


def _valid_execution_response(response: object, intent: BrokerIntentV1) -> bool:
    if type(response) is not BrokerTransportResponse or type(response.fds) is not tuple:
        return False
    if response.fds:
        return False
    try:
        validate_chpb_message(response.reply)
        return response.reply.request_id == intent.request_id
    except Exception:
        return False


def _response_fds(response: object) -> tuple[int, ...]:
    try:
        fds = response.fds
        if type(fds) not in (tuple, list):
            return ()
        valid = []
        for fd in fds:
            if type(fd) is int and fd >= 0 and fd not in valid:
                valid.append(fd)
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
        return BrokerIntentConsumeResult(BrokerIntentConsumeCode.EMPTY)
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
    try:
        response = execution.execute_intent(claimed.intent, plan)
        if not _valid_execution_response(response, claimed.intent):
            execution_failed = True
    except Exception:
        execution_failed = True
    if execution_failed:
        _close_response_fds(execution, response)
        _mark_terminal(
            store, claimed.claim_name, BrokerIntentConsumeCode.EXECUTION_FAILED
        )
        return BrokerIntentConsumeResult(BrokerIntentConsumeCode.EXECUTION_FAILED)
    _mark_terminal(store, claimed.claim_name, BrokerIntentConsumeCode.SUCCEEDED)
    return BrokerIntentConsumeResult(BrokerIntentConsumeCode.SUCCEEDED)


__all__ = (
    "BrokerExecutionComposition",
    "BrokerIntentConsumeCode",
    "BrokerIntentConsumeResult",
    "BrokerIntentConsumerError",
    "BrokerIntentResolver",
    "consume_one_broker_intent",
)
