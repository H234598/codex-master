from __future__ import annotations

import dataclasses
import hashlib
import inspect
import threading
import traceback
from dataclasses import FrozenInstanceError

import pytest

from codex_master.fleet_home_broker import OfflineBrokerPlan
from codex_master.fleet_home_broker_consumer import (
    BrokerExecutionComposition,
    BrokerIntentConsumeCode,
    BrokerIntentConsumeResult,
    BrokerIntentConsumerError,
    BrokerIntentResolver,
    consume_one_broker_intent,
)
from codex_master.fleet_home_broker_dispatch import BrokerDispatchOperations
import codex_master.fleet_home_broker_consumer as consumer
from codex_master.fleet_home_broker_identity import (
    BrokerIdentity,
    ImportClosure,
    ImportClosureEntry,
)
from codex_master.fleet_home_broker_intent import (
    BrokerIntentOperation,
    BrokerIntentV1,
    canonical_intent_payload,
    encode_broker_intent,
)
from codex_master.fleet_home_broker_intent_store import (
    BrokerIntentClaimBytes,
    BrokerIntentFileIdentity,
    claim_broker_intent,
)
from codex_master.fleet_home_broker_protocol import (
    BrokerReply,
    BrokerResultCode,
    CHPB_PROTOCOL,
    ChpbTransactionOperation,
    ChpbMessageKind,
    PrincipalBinding,
)
from codex_master.fleet_home_broker_transport import BrokerTransportResponse


class EmptyStore:
    def claim_next(self):
        return None


class UnusedResolver:
    def resolve_plan(self, intent):
        raise AssertionError("empty store must not resolve")


class UnusedExecution:
    def execute_intent(self, intent, plan):
        raise AssertionError("empty store must not execute")

    def execute(self, command):
        raise AssertionError("consumer must not invoke dispatch execute")

    def close(self, fd):
        raise AssertionError("empty store must not close")


def _intent(**changes: object) -> BrokerIntentV1:
    values: dict[str, object] = {
        "schema_version": 1,
        "intent_generation": 7,
        "operation": BrokerIntentOperation.PROVISION,
        "transaction_id": "2" * 32,
        "request_id": "1" * 32,
        "agent_id": "bee_1",
        "manifest_generation": 3,
        "unit_generation": 9,
        "policy_generation": 7,
        "fencing_epoch": 4,
        "store_uuid": "3" * 32,
        "slot_id": "slot-01",
        "mcs_pair": "c0,c1",
        "projection_digest": "a" * 64,
        "joint_release_id": "release-0.11.0",
        "server_digest": "b" * 64,
        "broker_manifest_digest": "c" * 64,
        "credential_binding_ref": "cred-bind-01",
        "credential_generation": 2,
        "created_at_unix_ms": 1_700_000_000_000,
        "expires_at_unix_ms": 1_700_000_030_000,
        "nonce": "d" * 32,
        "digest": "0" * 64,
    }
    values.update(changes)
    unsigned = BrokerIntentV1(**values)
    digest = hashlib.sha256(canonical_intent_payload(unsigned)).hexdigest()
    return dataclasses.replace(unsigned, digest=digest)


def _plan(intent: BrokerIntentV1) -> OfflineBrokerPlan:
    principal = PrincipalBinding(
        intent.agent_id,
        intent.manifest_generation,
        intent.unit_generation,
        17,
        29,
        "e" * 32,
        intent.mcs_pair,
        intent.fencing_epoch,
    )
    closure = ImportClosure((ImportClosureEntry("codex_master/probe.py", "d" * 64),))
    identity = BrokerIdentity(
        intent.agent_id,
        intent.manifest_generation,
        intent.mcs_pair,
        intent.slot_id,
        intent.policy_generation,
        intent.projection_digest,
        closure.digest(),
        intent.fencing_epoch,
    )
    return OfflineBrokerPlan(
        identity,
        closure,
        principal,
        ChpbTransactionOperation(intent.operation.value),
        intent.store_uuid,
        1,
    )


def _response(
    intent: BrokerIntentV1,
    *,
    request_id: str | None = None,
    fds: tuple[int, ...] = (),
) -> BrokerTransportResponse:
    return BrokerTransportResponse(
        BrokerReply(
            CHPB_PROTOCOL,
            ChpbMessageKind.REPLY,
            request_id or intent.request_id,
            BrokerResultCode.INVALID_MESSAGE,
            None,
            None,
        ),
        fds,
    )


IDENTITY = BrokerIntentFileIdentity(
    8, 101, 0o100600, 0, 0, 1, "system_u:object_r:codex_master_home_broker_state_t:s0"
)


class FakeStore:
    def __init__(
        self,
        claims: list[BrokerIntentClaimBytes] | None = None,
        *,
        terminal_error: Exception | None = None,
        terminal_result: object | None = None,
    ) -> None:
        self.claims = list(claims or ())
        self.terminal_error = terminal_error
        self.terminal_result = terminal_result
        self.terminals: list[tuple[str, bytes]] = []
        self.quarantines: list[tuple[str, str]] = []

    def claim_next(self) -> BrokerIntentClaimBytes | None:
        if not self.claims:
            return None
        return self.claims.pop(0)

    def mark_terminal(self, claim_name: str, payload: bytes) -> object | None:
        if self.terminal_error is not None:
            raise self.terminal_error
        self.terminals.append((claim_name, payload))
        return self.terminal_result

    def quarantine(self, claim_name: str, code: str) -> None:
        self.quarantines.append((claim_name, code))


class AtomicFakeStore(FakeStore):
    def __init__(self, claims: list[BrokerIntentClaimBytes]) -> None:
        super().__init__(claims)
        self.claim_lock = threading.Lock()

    def claim_next(self) -> BrokerIntentClaimBytes | None:
        with self.claim_lock:
            return super().claim_next()


class FakeResolver:
    def __init__(self, plan: OfflineBrokerPlan) -> None:
        self.plan = plan
        self.intents: list[BrokerIntentV1] = []

    def resolve_plan(self, intent: BrokerIntentV1) -> OfflineBrokerPlan:
        self.intents.append(intent)
        return self.plan


class FailingResolver:
    def __init__(self) -> None:
        self.intents: list[BrokerIntentV1] = []

    def resolve_plan(self, intent: BrokerIntentV1) -> OfflineBrokerPlan:
        self.intents.append(intent)
        raise RuntimeError("secret-value /host/path must stay private")


class FakeExecution:
    def __init__(
        self, response: BrokerTransportResponse, *, close_error: bool = False
    ) -> None:
        self.response = response
        self.close_error = close_error
        self.calls: list[tuple[BrokerIntentV1, OfflineBrokerPlan]] = []
        self.closed: list[int] = []

    def execute_intent(
        self, intent: BrokerIntentV1, plan: OfflineBrokerPlan
    ) -> BrokerTransportResponse:
        self.calls.append((intent, plan))
        return self.response

    def execute(self, command: object) -> BrokerTransportResponse:
        raise AssertionError("consumer must not invoke dispatch execute")

    def close(self, fd: int) -> None:
        self.closed.append(fd)
        if self.close_error:
            raise RuntimeError("secret-value /host/path must stay private")


class FailingExecution:
    def __init__(self) -> None:
        self.calls: list[tuple[BrokerIntentV1, OfflineBrokerPlan]] = []
        self.closed: list[int] = []

    def execute_intent(
        self, intent: BrokerIntentV1, plan: OfflineBrokerPlan
    ) -> BrokerTransportResponse:
        self.calls.append((intent, plan))
        raise RuntimeError("secret-value /host/path must stay private")

    def execute(self, command: object) -> BrokerTransportResponse:
        raise AssertionError("consumer must not invoke dispatch execute")

    def close(self, fd: int) -> None:
        self.closed.append(fd)


def test_public_results_and_errors_are_frozen_typed_and_value_free() -> None:
    assert consumer.__all__ == (
        "BrokerExecutionComposition",
        "BrokerIntentConsumeCode",
        "BrokerIntentConsumeResult",
        "BrokerIntentConsumerError",
        "BrokerIntentResolver",
        "consume_one_broker_intent",
    )
    assert issubclass(BrokerIntentConsumerError, ValueError)
    assert dataclasses.is_dataclass(BrokerIntentConsumeResult)
    assert BrokerIntentConsumeResult.__dataclass_params__.frozen
    assert hasattr(BrokerIntentConsumeResult, "__slots__")
    assert tuple(
        field.name for field in dataclasses.fields(BrokerIntentConsumeResult)
    ) == ("code",)
    with pytest.raises(FrozenInstanceError):
        BrokerIntentConsumeResult(BrokerIntentConsumeCode.EMPTY).code = (  # type: ignore[misc]
            BrokerIntentConsumeCode.SUCCEEDED
        )
    with pytest.raises(BrokerIntentConsumerError) as caught:
        BrokerIntentConsumeResult("secret-value /host/path")  # type: ignore[arg-type]
    assert caught.value.code is BrokerIntentConsumeCode.INVALID_RESULT
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert "secret-value" not in str(caught.value)
    assert getattr(BrokerIntentResolver, "_is_protocol", False)
    assert getattr(BrokerExecutionComposition, "_is_protocol", False)
    assert tuple(inspect.signature(BrokerIntentResolver.resolve_plan).parameters) == (
        "self",
        "intent",
    )
    assert tuple(
        inspect.signature(BrokerExecutionComposition.execute_intent).parameters
    ) == ("self", "intent", "plan")


def test_execution_composition_reuses_existing_dispatch_close_contract() -> None:
    assert BrokerDispatchOperations in BrokerExecutionComposition.__mro__
    assert tuple(inspect.signature(BrokerExecutionComposition.close).parameters) == (
        "self",
        "fd",
    )


def test_empty_store_returns_typed_empty_result_without_downstream_calls() -> None:
    result = consume_one_broker_intent(
        EmptyStore(), UnusedResolver(), UnusedExecution(), now_unix_ms=1
    )

    assert type(result) is BrokerIntentConsumeResult
    assert result.code is BrokerIntentConsumeCode.EMPTY


def test_claimed_revalidated_intent_executes_once_then_writes_typed_terminal() -> None:
    intent = _intent()
    claim = BrokerIntentClaimBytes(
        ".claim-intent-00000000000000000007-" + intent.nonce + ".json",
        encode_broker_intent(intent),
        IDENTITY,
    )
    store = FakeStore([claim])
    resolver = FakeResolver(_plan(intent))
    execution = FakeExecution(_response(intent))

    result = consume_one_broker_intent(
        store,
        resolver,
        execution,
        now_unix_ms=intent.created_at_unix_ms + 1,
    )

    assert result.code is BrokerIntentConsumeCode.SUCCEEDED
    assert resolver.intents == [intent]
    assert execution.calls == [(intent, resolver.plan)]
    assert store.terminals == [(claim.claim_name, b'{"result":"succeeded"}\n')]
    assert intent.broker_manifest_digest.encode("ascii") not in store.terminals[0][1]
    assert intent.server_digest.encode("ascii") not in store.terminals[0][1]
    assert intent.credential_binding_ref.encode("ascii") not in store.terminals[0][1]


def test_resolver_drift_is_terminal_before_execution() -> None:
    intent = _intent()
    claim = BrokerIntentClaimBytes(
        ".claim-intent-00000000000000000007-" + intent.nonce + ".json",
        encode_broker_intent(intent),
        IDENTITY,
    )
    store = FakeStore([claim])
    resolver = FakeResolver(dataclasses.replace(_plan(intent), store_uuid="4" * 32))
    execution = UnusedExecution()

    result = consume_one_broker_intent(
        store,
        resolver,
        execution,
        now_unix_ms=intent.created_at_unix_ms + 1,
    )

    assert result.code is BrokerIntentConsumeCode.RESOLVER_DRIFT
    assert resolver.intents == [intent]
    assert store.terminals == [(claim.claim_name, b'{"result":"resolver_drift"}\n')]


@pytest.mark.parametrize(
    "drift",
    (
        lambda plan: dataclasses.replace(
            plan,
            expected_principal=dataclasses.replace(
                plan.expected_principal, agent_id="bee_2"
            ),
        ),
        lambda plan: dataclasses.replace(
            plan,
            expected_principal=dataclasses.replace(
                plan.expected_principal, manifest_generation=4
            ),
        ),
        lambda plan: dataclasses.replace(
            plan,
            expected_principal=dataclasses.replace(
                plan.expected_principal, unit_generation=10
            ),
        ),
        lambda plan: dataclasses.replace(
            plan, operation=ChpbTransactionOperation.REPLACE
        ),
        lambda plan: dataclasses.replace(plan, store_uuid="4" * 32),
        lambda plan: dataclasses.replace(
            plan,
            expected_principal=dataclasses.replace(
                plan.expected_principal, mcs_pair="c1,c2"
            ),
        ),
        lambda plan: dataclasses.replace(
            plan,
            identity=dataclasses.replace(plan.identity, slot_snapshot="slot-02"),
        ),
        lambda plan: dataclasses.replace(
            plan,
            identity=dataclasses.replace(plan.identity, policy_generation=8),
        ),
        lambda plan: dataclasses.replace(
            plan,
            identity=dataclasses.replace(plan.identity, projection_digest="b" * 64),
        ),
        lambda plan: dataclasses.replace(
            plan,
            expected_principal=dataclasses.replace(
                plan.expected_principal, fencing_epoch=5
            ),
        ),
    ),
)
def test_revalidation_fails_closed_for_each_intent_bound_plan_field(drift) -> None:
    intent = _intent()
    claim = BrokerIntentClaimBytes(
        ".claim-intent-00000000000000000007-" + intent.nonce + ".json",
        encode_broker_intent(intent),
        IDENTITY,
    )
    store = FakeStore([claim])
    execution = UnusedExecution()

    result = consume_one_broker_intent(
        store,
        FakeResolver(drift(_plan(intent))),
        execution,
        now_unix_ms=intent.created_at_unix_ms + 1,
    )

    assert result.code is BrokerIntentConsumeCode.RESOLVER_DRIFT
    assert store.terminals == [(claim.claim_name, b'{"result":"resolver_drift"}\n')]


def test_resolver_failure_is_redacted_and_terminal_before_execution() -> None:
    intent = _intent()
    claim = BrokerIntentClaimBytes(
        ".claim-intent-00000000000000000007-" + intent.nonce + ".json",
        encode_broker_intent(intent),
        IDENTITY,
    )
    store = FakeStore([claim])
    resolver = FailingResolver()

    result = consume_one_broker_intent(
        store,
        resolver,
        UnusedExecution(),
        now_unix_ms=intent.created_at_unix_ms + 1,
    )

    assert result.code is BrokerIntentConsumeCode.RESOLUTION_FAILED
    assert resolver.intents == [intent]
    assert store.terminals == [(claim.claim_name, b'{"result":"resolution_failed"}\n')]
    assert "secret-value" not in repr(result)


def test_execution_failure_is_redacted_and_terminal_without_effect_retry() -> None:
    intent = _intent()
    claim = BrokerIntentClaimBytes(
        ".claim-intent-00000000000000000007-" + intent.nonce + ".json",
        encode_broker_intent(intent),
        IDENTITY,
    )
    store = FakeStore([claim])
    execution = FailingExecution()

    result = consume_one_broker_intent(
        store,
        FakeResolver(_plan(intent)),
        execution,
        now_unix_ms=intent.created_at_unix_ms + 1,
    )

    assert result.code is BrokerIntentConsumeCode.EXECUTION_FAILED
    assert len(execution.calls) == 1
    assert store.terminals == [(claim.claim_name, b'{"result":"execution_failed"}\n')]
    assert "secret-value" not in repr(result)
    assert "host/path" not in store.terminals[0][1].decode("ascii")
    restart_execution = FakeExecution(_response(intent))
    restart = consume_one_broker_intent(
        store,
        UnusedResolver(),
        restart_execution,
        now_unix_ms=intent.created_at_unix_ms + 1,
    )
    assert restart.code is BrokerIntentConsumeCode.EMPTY
    assert restart_execution.calls == []


def test_execution_response_with_fd_is_terminal_failure_without_fd_lifecycle() -> None:
    intent = _intent()
    claim = BrokerIntentClaimBytes(
        ".claim-intent-00000000000000000007-" + intent.nonce + ".json",
        encode_broker_intent(intent),
        IDENTITY,
    )
    store = FakeStore([claim])
    execution = FakeExecution(_response(intent, fds=(41,)))

    result = consume_one_broker_intent(
        store,
        FakeResolver(_plan(intent)),
        execution,
        now_unix_ms=intent.created_at_unix_ms + 1,
    )

    assert result.code is BrokerIntentConsumeCode.EXECUTION_FAILED
    assert len(execution.calls) == 1
    assert store.terminals == [(claim.claim_name, b'{"result":"execution_failed"}\n')]


def test_terminal_write_failure_is_typed_redacted_and_not_retried_after_restart() -> (
    None
):
    intent = _intent()
    claim = BrokerIntentClaimBytes(
        ".claim-intent-00000000000000000007-" + intent.nonce + ".json",
        encode_broker_intent(intent),
        IDENTITY,
    )
    store = FakeStore(
        [claim], terminal_error=OSError("secret-value /host/path must stay private")
    )
    execution = FakeExecution(_response(intent))

    with pytest.raises(BrokerIntentConsumerError) as caught:
        consume_one_broker_intent(
            store,
            FakeResolver(_plan(intent)),
            execution,
            now_unix_ms=intent.created_at_unix_ms + 1,
        )

    assert caught.value.code is BrokerIntentConsumeCode.TERMINAL_WRITE_FAILED
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert "secret-value" not in "".join(traceback.format_exception(caught.value))
    assert len(execution.calls) == 1
    restart_execution = FakeExecution(_response(intent))
    restart = consume_one_broker_intent(
        store,
        UnusedResolver(),
        restart_execution,
        now_unix_ms=intent.created_at_unix_ms + 1,
    )
    assert restart.code is BrokerIntentConsumeCode.EMPTY
    assert restart_execution.calls == []


def test_terminal_non_none_result_is_typed_redacted_and_not_retried_after_restart() -> (
    None
):
    intent = _intent()
    claim = BrokerIntentClaimBytes(
        ".claim-intent-00000000000000000007-" + intent.nonce + ".json",
        encode_broker_intent(intent),
        IDENTITY,
    )
    store = FakeStore([claim], terminal_result="secret-value /host/path")
    execution = FakeExecution(_response(intent))

    with pytest.raises(BrokerIntentConsumerError) as caught:
        consume_one_broker_intent(
            store,
            FakeResolver(_plan(intent)),
            execution,
            now_unix_ms=intent.created_at_unix_ms + 1,
        )

    assert caught.value.code is BrokerIntentConsumeCode.TERMINAL_WRITE_FAILED
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert "secret-value" not in "".join(traceback.format_exception(caught.value))
    assert len(execution.calls) == 1
    restart_execution = FakeExecution(_response(intent))
    restart = consume_one_broker_intent(
        store,
        UnusedResolver(),
        restart_execution,
        now_unix_ms=intent.created_at_unix_ms + 1,
    )
    assert restart.code is BrokerIntentConsumeCode.EMPTY
    assert restart_execution.calls == []


def test_expired_claim_is_quarantined_before_resolution_or_execution() -> None:
    intent = _intent()
    claim = BrokerIntentClaimBytes(
        ".claim-intent-00000000000000000007-" + intent.nonce + ".json",
        encode_broker_intent(intent),
        IDENTITY,
    )
    store = FakeStore([claim])

    result = consume_one_broker_intent(
        store,
        UnusedResolver(),
        UnusedExecution(),
        now_unix_ms=intent.expires_at_unix_ms,
    )

    assert result.code is BrokerIntentConsumeCode.EMPTY
    assert store.quarantines == [(claim.claim_name, "expired")]
    assert len(store.quarantines[0][1].encode("ascii")) <= 64
    assert store.terminals == []


def test_two_independent_consumers_racing_one_transaction_execute_it_once() -> None:
    intent = _intent()
    claim = BrokerIntentClaimBytes(
        ".claim-intent-00000000000000000007-" + intent.nonce + ".json",
        encode_broker_intent(intent),
        IDENTITY,
    )
    store = AtomicFakeStore([claim])
    start = threading.Barrier(3)
    results: list[BrokerIntentConsumeResult] = []
    first_execution = FakeExecution(_response(intent))
    second_execution = FakeExecution(_response(intent))

    def consume(execution: FakeExecution) -> None:
        start.wait()
        results.append(
            consume_one_broker_intent(
                store,
                FakeResolver(_plan(intent)),
                execution,
                now_unix_ms=intent.created_at_unix_ms + 1,
            )
        )

    first = threading.Thread(target=consume, args=(first_execution,))
    second = threading.Thread(target=consume, args=(second_execution,))
    first.start()
    second.start()
    start.wait()
    first.join()
    second.join()

    assert sorted(result.code.value for result in results) == ["empty", "succeeded"]
    assert len(first_execution.calls) + len(second_execution.calls) == 1
    assert store.terminals == [(claim.claim_name, b'{"result":"succeeded"}\n')]


def test_restart_after_atomic_claim_cannot_reexecute_transaction_or_request() -> None:
    intent = _intent()
    claim = BrokerIntentClaimBytes(
        ".claim-intent-00000000000000000007-" + intent.nonce + ".json",
        encode_broker_intent(intent),
        IDENTITY,
    )
    store = FakeStore([claim])

    claimed = claim_broker_intent(store, now_unix_ms=intent.created_at_unix_ms + 1)
    assert claimed is not None
    assert claimed.intent.transaction_id == intent.transaction_id
    assert claimed.intent.request_id == intent.request_id

    restart_execution = FakeExecution(_response(intent))
    result = consume_one_broker_intent(
        store,
        UnusedResolver(),
        restart_execution,
        now_unix_ms=intent.created_at_unix_ms + 1,
    )

    assert result.code is BrokerIntentConsumeCode.EMPTY
    assert restart_execution.calls == []
    assert store.terminals == []


def test_wrong_reply_type_is_terminal_execution_failure_without_restart_retry() -> None:
    intent = _intent()
    claim = BrokerIntentClaimBytes(
        ".claim-intent-00000000000000000007-" + intent.nonce + ".json",
        encode_broker_intent(intent),
        IDENTITY,
    )
    store = FakeStore([claim])
    execution = FakeExecution(BrokerTransportResponse(object(), ()))

    result = consume_one_broker_intent(
        store,
        FakeResolver(_plan(intent)),
        execution,
        now_unix_ms=intent.created_at_unix_ms + 1,
    )

    assert result.code is BrokerIntentConsumeCode.EXECUTION_FAILED
    assert len(execution.calls) == 1
    assert store.terminals == [(claim.claim_name, b'{"result":"execution_failed"}\n')]
    restart_execution = FakeExecution(_response(intent))
    restart = consume_one_broker_intent(
        store,
        UnusedResolver(),
        restart_execution,
        now_unix_ms=intent.created_at_unix_ms + 1,
    )
    assert restart.code is BrokerIntentConsumeCode.EMPTY
    assert restart_execution.calls == []


def test_mismatched_reply_request_id_is_terminal_execution_failure() -> None:
    intent = _intent()
    claim = BrokerIntentClaimBytes(
        ".claim-intent-00000000000000000007-" + intent.nonce + ".json",
        encode_broker_intent(intent),
        IDENTITY,
    )
    store = FakeStore([claim])
    execution = FakeExecution(_response(intent, request_id="9" * 32))

    result = consume_one_broker_intent(
        store,
        FakeResolver(_plan(intent)),
        execution,
        now_unix_ms=intent.created_at_unix_ms + 1,
    )

    assert result.code is BrokerIntentConsumeCode.EXECUTION_FAILED
    assert len(execution.calls) == 1
    assert store.terminals == [(claim.claim_name, b'{"result":"execution_failed"}\n')]


@pytest.mark.parametrize(
    ("fds", "expected_closed"),
    (
        ((73, 73, -1, True, "bad", 74), [73, 74]),
        ([75, 75, True, "bad"], [75]),
    ),
    ids=("invalid_entries", "invalid_container"),
)
def test_rejected_response_closes_unique_valid_fds_without_masking_terminalization(
    fds: object, expected_closed: list[int]
) -> None:
    intent = _intent()
    claim = BrokerIntentClaimBytes(
        ".claim-intent-00000000000000000007-" + intent.nonce + ".json",
        encode_broker_intent(intent),
        IDENTITY,
    )
    store = FakeStore([claim])
    response = BrokerTransportResponse(_response(intent).reply, fds)  # type: ignore[arg-type]
    execution = FakeExecution(response, close_error=True)

    result = consume_one_broker_intent(
        store,
        FakeResolver(_plan(intent)),
        execution,
        now_unix_ms=intent.created_at_unix_ms + 1,
    )

    assert result.code is BrokerIntentConsumeCode.EXECUTION_FAILED
    assert execution.closed == expected_closed
    assert store.terminals == [(claim.claim_name, b'{"result":"execution_failed"}\n')]
    assert "secret-value" not in repr(result)
    restart_execution = FakeExecution(_response(intent))
    restart = consume_one_broker_intent(
        store,
        UnusedResolver(),
        restart_execution,
        now_unix_ms=intent.created_at_unix_ms + 1,
    )
    assert restart.code is BrokerIntentConsumeCode.EMPTY
    assert restart_execution.calls == []
