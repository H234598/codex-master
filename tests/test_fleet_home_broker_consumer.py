from __future__ import annotations

import base64
import dataclasses
import errno
import hashlib
import inspect
import json
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
    LinuxBrokerIntentStore,
    claim_broker_intent,
)
from codex_master.fleet_home_broker_identity_contract import ObjectIdentity
from codex_master.fleet_home_broker_linux_contract import PinnedFd
from codex_master.fleet_home_broker_protocol import (
    BrokerCheckpoint,
    BrokerObjectState,
    BrokerObservation,
    BrokerRegistryState,
    BrokerReply,
    BrokerResultCode,
    CHPB_PROTOCOL,
    ChpbTransactionOperation,
    ChpbMessageKind,
    PolicyBinding,
    PrincipalBinding,
    TransactionBinding,
    TransactionStatus,
    b2a_phase_for_checkpoint,
)
from codex_master.fleet_home_broker_transport import BrokerTransportResponse


class EmptyStore:
    def claim_next(self):
        return None

    def recover_next(self):
        return None

    def release_claim(self, claim_name):
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


def _binding(intent: BrokerIntentV1, **changes: object) -> TransactionBinding:
    binding = TransactionBinding(
        ChpbTransactionOperation(intent.operation.value),
        intent.transaction_id,
        intent.store_uuid,
        _plan(intent).expected_principal,
        PolicyBinding(intent.policy_generation, intent.projection_digest),
    )
    return dataclasses.replace(binding, **changes)


def _response(
    intent: BrokerIntentV1,
    *,
    request_id: str | None = None,
    result: BrokerResultCode = BrokerResultCode.COMMITTED,
    binding: TransactionBinding | None = None,
    fds: tuple[int, ...] = (),
) -> BrokerTransportResponse:
    transaction_binding = binding or _binding(intent)
    checkpoint = {
        BrokerResultCode.COMMITTED: BrokerCheckpoint.COMMITTED,
        BrokerResultCode.ROLLED_BACK: BrokerCheckpoint.ROLLED_BACK,
        BrokerResultCode.BLOCKED_DRIFT: BrokerCheckpoint.BLOCKED_DRIFT,
    }[result]
    observation = {
        BrokerCheckpoint.COMMITTED: BrokerObservation(
            BrokerObjectState.FINAL_COMPLETE, BrokerRegistryState.CURRENT, 1
        ),
        BrokerCheckpoint.ROLLED_BACK: BrokerObservation(
            BrokerObjectState.ROLLED_BACK, BrokerRegistryState.NOT_APPLICABLE, 1
        ),
        BrokerCheckpoint.BLOCKED_DRIFT: BrokerObservation(
            BrokerObjectState.DRIFT, BrokerRegistryState.FOREIGN, 1
        ),
    }[checkpoint]
    return BrokerTransportResponse(
        BrokerReply(
            CHPB_PROTOCOL,
            ChpbMessageKind.REPLY,
            request_id or intent.request_id,
            result,
            TransactionStatus(
                transaction_binding,
                b2a_phase_for_checkpoint(checkpoint),
                checkpoint,
                observation,
                1,
                result,
            ),
            None,
        ),
        fds,
    )


def _invalid_message_response(intent: BrokerIntentV1) -> BrokerTransportResponse:
    return BrokerTransportResponse(
        BrokerReply(
            CHPB_PROTOCOL,
            ChpbMessageKind.REPLY,
            intent.request_id,
            BrokerResultCode.INVALID_MESSAGE,
            None,
            None,
        ),
        (),
    )


IDENTITY = BrokerIntentFileIdentity(
    8, 101, 0o100600, 0, 0, 1, "system_u:object_r:codex_master_home_broker_state_t:s0"
)


class FakeStore:
    def __init__(
        self,
        claims: list[BrokerIntentClaimBytes] | None = None,
        *,
        recoveries: list[BrokerIntentClaimBytes] | None = None,
        terminal_error: Exception | None = None,
        terminal_result: object | None = None,
    ) -> None:
        self.claims = list(claims or ())
        self.recoveries = list(recoveries or ())
        self.terminal_error = terminal_error
        self.terminal_result = terminal_result
        self.terminals: list[tuple[str, bytes]] = []
        self.quarantines: list[tuple[str, str]] = []
        self.releases: list[str] = []

    def claim_next(self) -> BrokerIntentClaimBytes | None:
        if not self.claims:
            return None
        return self.claims.pop(0)

    def recover_next(self) -> BrokerIntentClaimBytes | None:
        if not self.recoveries:
            return None
        return self.recoveries.pop(0)

    def mark_terminal(self, claim_name: str, payload: bytes) -> object | None:
        if self.terminal_error is not None:
            raise self.terminal_error
        self.terminals.append((claim_name, payload))
        return self.terminal_result

    def quarantine(self, claim_name: str, code: str) -> None:
        self.quarantines.append((claim_name, code))

    def release_claim(self, claim_name: str) -> None:
        self.releases.append(claim_name)


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


class RecoveryStateExecution:
    """State fake for the future execution composition, not a WAL fake."""

    def __init__(
        self,
        intent: BrokerIntentV1,
        *,
        checkpoint: BrokerCheckpoint | None,
        evidence: str = "attested",
        effect_count: int = 0,
    ) -> None:
        self.intent = intent
        self.checkpoint = checkpoint
        self.evidence = evidence
        self.effect_count = effect_count
        self.execute_attempts = 0
        self.resume_calls: list[tuple[object, ...]] = []
        self.started_transaction_ids: list[str] = []
        self.closed: list[int] = []

    def execute_intent(
        self, intent: BrokerIntentV1, plan: OfflineBrokerPlan
    ) -> BrokerTransportResponse:
        self.execute_attempts += 1
        raise AssertionError("recovered claims must not execute as fresh intents")

    def resume_intent(
        self, intent: BrokerIntentV1, plan: OfflineBrokerPlan, context: object
    ) -> BrokerTransportResponse:
        self.resume_calls.append((intent, plan, context))
        if self.evidence != "attested":
            return _response(intent, result=BrokerResultCode.BLOCKED_DRIFT)
        assert getattr(context, "transaction_id") == intent.transaction_id
        expected = {
            BrokerIntentOperation.PROVISION: BrokerObservation(
                BrokerObjectState.ABSENT, BrokerRegistryState.NOT_APPLICABLE, 0
            ),
            BrokerIntentOperation.REPLACE: BrokerObservation(
                BrokerObjectState.REPLACEMENT_ORIGINAL,
                BrokerRegistryState.NOT_APPLICABLE,
                0,
            ),
            BrokerIntentOperation.DEPROVISION: BrokerObservation(
                BrokerObjectState.FINAL_COMPLETE,
                BrokerRegistryState.NOT_APPLICABLE,
                0,
            ),
        }[intent.operation]
        assert getattr(context, "initial_observation") == expected
        if self.checkpoint is None:
            self.started_transaction_ids.append(intent.transaction_id)
            self.effect_count += 1
        return _response(intent)

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
        "BrokerIntentResumeContext",
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
    assert tuple(
        inspect.signature(BrokerExecutionComposition.resume_intent).parameters
    ) == ("self", "intent", "plan", "context")
    context_type = getattr(consumer, "BrokerIntentResumeContext")
    assert dataclasses.is_dataclass(context_type)
    assert context_type.__dataclass_params__.frozen
    assert hasattr(context_type, "__slots__")


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


def test_fresh_linux_store_and_consumer_resume_a_crashed_atomic_claim_once() -> None:
    class SharedLinuxIntentFiles:
        def __init__(self, name: str, payload: bytes) -> None:
            self.files = {name: payload}
            self.identities = {name: ObjectIdentity(8, 1001, 0o100600, 0, 0, 1)}
            self.labels = {
                name: "system_u:object_r:codex_master_home_broker_state_t:s0"
            }
            self.parent = ObjectIdentity(8, 100, 0o40700, 0, 0, 2)
            self.parent_label = "system_u:object_r:codex_master_home_broker_state_t:s0"
            self.next_fd = 10
            self.fd_names: dict[int, str] = {}
            self.fd_identities: dict[int, ObjectIdentity] = {}
            self.fd_labels: dict[int, str] = {}
            self.fd_flags: dict[int, int] = {}
            self.locked_fds: dict[int, tuple[int, int]] = {}
            self.locked_identities: set[tuple[int, int]] = set()

        def openat2(self, parent_fd: int, name: str, how: object) -> PinnedFd:
            if name not in self.files:
                if not (getattr(how, "flags", 0) & 0o200):
                    raise FileNotFoundError(errno.ENOENT, "missing")
                self.files[name] = b""
                self.identities[name] = ObjectIdentity(
                    8, 1000 + self.next_fd, 0o100600, 0, 0, 1
                )
                self.labels[name] = self.parent_label
            elif getattr(how, "flags", 0) & 0o200:
                raise FileExistsError(errno.EEXIST, "exists")
            fd = self.next_fd
            self.next_fd += 1
            self.fd_names[fd] = name
            self.fd_identities[fd] = self.identities[name]
            self.fd_labels[fd] = self.labels[name]
            self.fd_flags[fd] = getattr(how, "flags")
            return PinnedFd(fd, self.fd_identities[fd])

        def stat_fd(self, fd: int) -> ObjectIdentity:
            return self.parent if fd == 7 else self.fd_identities[fd]

        def selinux_label(self, fd: int) -> str:
            return self.parent_label if fd == 7 else self.fd_labels[fd]

        def list_names(self, parent_fd: int) -> tuple[str, ...]:
            return tuple(sorted(self.files))

        def read_all(self, fd: int) -> bytes:
            return self.files[self.fd_names[fd]]

        def write_all(self, fd: int, payload: bytes) -> None:
            self.files[self.fd_names[fd]] = payload

        def truncate(self, fd: int) -> None:
            self.files[self.fd_names[fd]] = b""

        def fsync(self, fd: int) -> None:
            return None

        def renameat2_noreplace(
            self, parent_fd: int, old_name: str, new_name: str
        ) -> None:
            if new_name in self.files:
                raise FileExistsError
            self.files[new_name] = self.files.pop(old_name)
            self.identities[new_name] = self.identities.pop(old_name)
            self.labels[new_name] = self.labels.pop(old_name)
            for fd, name in self.fd_names.items():
                if name == old_name:
                    self.fd_names[fd] = new_name

        def lock_exclusive_nonblocking(self, fd: int) -> None:
            identity = self.fd_identities[fd]
            key = (identity.dev, identity.ino)
            if key in self.locked_identities:
                raise BlockingIOError
            self.locked_identities.add(key)
            self.locked_fds[fd] = key

        def unlinkat(self, parent_fd: int, name: str) -> None:
            self.files.pop(name, None)
            self.identities.pop(name, None)
            self.labels.pop(name, None)

        def close(self, fd: int) -> None:
            key = self.locked_fds.pop(fd, None)
            if key is not None:
                self.locked_identities.remove(key)
            self.fd_names.pop(fd, None)
            self.fd_identities.pop(fd, None)
            self.fd_labels.pop(fd, None)
            self.fd_flags.pop(fd, None)

        def crash(self) -> None:
            for fd in tuple(self.locked_fds):
                self.close(fd)

    class LocalResolver:
        def __init__(self, plan: OfflineBrokerPlan) -> None:
            self.plan = plan
            self.intents: list[BrokerIntentV1] = []

        def resolve_plan(self, intent: BrokerIntentV1) -> OfflineBrokerPlan:
            self.intents.append(intent)
            return self.plan

    class LocalResumeExecution:
        def __init__(self) -> None:
            self.resume_calls: list[
                tuple[BrokerIntentV1, OfflineBrokerPlan, object]
            ] = []
            self.execute_calls = 0
            self.effects = 0

        def execute_intent(
            self, intent: BrokerIntentV1, plan: OfflineBrokerPlan
        ) -> BrokerTransportResponse:
            self.execute_calls += 1
            raise AssertionError("recovered claims must not use fresh execution")

        def resume_intent(
            self, intent: BrokerIntentV1, plan: OfflineBrokerPlan, context: object
        ) -> BrokerTransportResponse:
            self.resume_calls.append((intent, plan, context))
            assert getattr(context, "transaction_id") == intent.transaction_id
            self.effects += 1
            return _response(intent)

        def execute(self, command: object) -> BrokerTransportResponse:
            raise AssertionError("consumer must not invoke dispatch execute")

        def close(self, fd: int) -> None:
            raise AssertionError("successful recovery must not close response FDs")

    intent = _intent()
    final_name = "intent-00000000000000000007-" + intent.nonce + ".json"
    operations = SharedLinuxIntentFiles(final_name, encode_broker_intent(intent))
    parent_identity = BrokerIntentFileIdentity(
        8, 100, 0o40700, 0, 0, 2, operations.parent_label
    )
    crashed_store = LinuxBrokerIntentStore(operations, 7, parent_identity)
    claimed = crashed_store.claim_next()
    assert claimed is not None
    assert claimed.claim_name == ".claim-" + final_name
    operations.crash()

    recovered_store = LinuxBrokerIntentStore(operations, 7, parent_identity)
    resolver = LocalResolver(_plan(intent))
    execution = LocalResumeExecution()
    result = consume_one_broker_intent(
        recovered_store,
        resolver,
        execution,
        now_unix_ms=intent.created_at_unix_ms + 1,
    )

    assert result.code is BrokerIntentConsumeCode.SUCCEEDED
    assert resolver.intents == [intent]
    assert execution.execute_calls == 0
    assert len(execution.resume_calls) == 1
    resumed_intent, resumed_plan, context = execution.resume_calls[0]
    assert resumed_intent == intent
    assert resumed_plan is resolver.plan
    assert getattr(context, "transaction_id") == intent.transaction_id
    assert execution.effects == 1
    assert len(operations.files) == 2
    assert sum(name.startswith(".terminal-evidence-") for name in operations.files) == 1
    assert sum(name.startswith(".terminal-commit-") for name in operations.files) == 1
    assert operations.locked_fds == {}

    terminal_restart = consume_one_broker_intent(
        LinuxBrokerIntentStore(operations, 7, parent_identity),
        UnusedResolver(),
        UnusedExecution(),
        now_unix_ms=intent.created_at_unix_ms + 1,
    )

    assert terminal_restart.code is BrokerIntentConsumeCode.EMPTY
    assert execution.effects == 1

    recovered_claim_name = (
        ".recover-intent-00000000000000000007-" + intent.nonce + ".json"
    )
    name_digest = hashlib.sha256(recovered_claim_name.encode("ascii")).hexdigest()
    evidence_name = f".terminal-evidence-{name_digest}.json"
    evidence = (
        json.dumps(
            {
                "claim_name": recovered_claim_name,
                "intent_b64": base64.b64encode(encode_broker_intent(intent)).decode(
                    "ascii"
                ),
                "result": "succeeded",
                "schema_version": 1,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")
    commit_name = f".terminal-commit-{name_digest}.json"
    commit = (
        json.dumps(
            {
                "evidence_sha256": hashlib.sha256(evidence).hexdigest(),
                "schema_version": 1,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")

    for crash_point, additions, terminal in (
        ("after_temp_create", {".tmp-terminal-evidence-crash-a.json": b""}, False),
        (
            "after_partial_write",
            {".tmp-terminal-evidence-crash-b.json": evidence[:9]},
            False,
        ),
        (
            "after_file_fsync_before_publish",
            {".tmp-terminal-evidence-crash-c.json": evidence},
            False,
        ),
        ("after_publish_before_parent_fsync", {evidence_name: evidence}, False),
        (
            "after_parent_fsync_before_commit",
            {evidence_name: evidence},
            False,
        ),
        (
            "after_commit_file_fsync",
            {
                evidence_name: evidence,
                ".tmp-terminal-commit-crash-d.json": commit,
            },
            False,
        ),
        (
            "after_durable_terminal_record_before_claim_finalization",
            {evidence_name: evidence, commit_name: commit},
            True,
        ),
    ):
        crashed_operations = SharedLinuxIntentFiles(
            recovered_claim_name, encode_broker_intent(intent)
        )
        crashed_operations.files.update(additions)
        for index, name in enumerate(additions, start=2000):
            crashed_operations.identities[name] = ObjectIdentity(
                8, index, 0o100600, 0, 0, 1
            )
            crashed_operations.labels[name] = crashed_operations.parent_label
        crashed_store = LinuxBrokerIntentStore(crashed_operations, 7, parent_identity)
        crash_resolver = LocalResolver(_plan(intent))
        crash_execution = LocalResumeExecution()
        crash_result = consume_one_broker_intent(
            crashed_store,
            crash_resolver if not terminal else UnusedResolver(),
            crash_execution if not terminal else UnusedExecution(),
            now_unix_ms=intent.created_at_unix_ms + 1,
        )

        if terminal:
            assert crash_result.code is BrokerIntentConsumeCode.EMPTY, crash_point
            assert recovered_claim_name not in crashed_operations.files
            continue
        assert crash_result.code is BrokerIntentConsumeCode.SUCCEEDED, crash_point
        assert crash_execution.execute_calls == 0
        assert crash_execution.effects == 1
        assert len(crash_execution.resume_calls) == 1
        assert (
            crash_execution.resume_calls[0][0].transaction_id == intent.transaction_id
        )
        assert crash_execution.resume_calls[0][0].request_id == intent.request_id

    evidence_only_claim_name = (
        ".claim-intent-00000000000000000007-" + intent.nonce + ".json"
    )
    evidence_only_digest = hashlib.sha256(
        evidence_only_claim_name.encode("ascii")
    ).hexdigest()
    evidence_only_name = f".terminal-evidence-{evidence_only_digest}.json"
    evidence_only = (
        json.dumps(
            {
                "claim_name": evidence_only_claim_name,
                "intent_b64": base64.b64encode(encode_broker_intent(intent)).decode(
                    "ascii"
                ),
                "result": "succeeded",
                "schema_version": 1,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")
    evidence_only_commit_name = f".terminal-commit-{evidence_only_digest}.json"
    evidence_only_commit = (
        json.dumps(
            {
                "evidence_sha256": hashlib.sha256(evidence_only).hexdigest(),
                "schema_version": 1,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")
    evidence_only_operations = SharedLinuxIntentFiles(
        evidence_only_claim_name, encode_broker_intent(intent)
    )
    evidence_only_operations.files[evidence_only_name] = evidence_only
    evidence_only_operations.identities[evidence_only_name] = ObjectIdentity(
        8, 3001, 0o100600, 0, 0, 1
    )
    evidence_only_operations.labels[evidence_only_name] = (
        evidence_only_operations.parent_label
    )
    evidence_only_execution = LocalResumeExecution()

    evidence_only_result = consume_one_broker_intent(
        LinuxBrokerIntentStore(evidence_only_operations, 7, parent_identity),
        LocalResolver(_plan(intent)),
        evidence_only_execution,
        now_unix_ms=intent.created_at_unix_ms + 1,
    )

    assert evidence_only_result.code is BrokerIntentConsumeCode.SUCCEEDED
    assert evidence_only_execution.execute_calls == 0
    assert evidence_only_execution.effects == 1
    assert len(evidence_only_execution.resume_calls) == 1
    assert (
        evidence_only_execution.resume_calls[0][0].transaction_id
        == intent.transaction_id
    )
    assert evidence_only_operations.files == {
        evidence_only_name: evidence_only,
        evidence_only_commit_name: evidence_only_commit,
    }
    assert not any("recover" in name for name in evidence_only_operations.files)


def test_recovered_claim_resumes_the_same_intent_transaction_after_crash_before_wal() -> (
    None
):
    assert "recovered" in BrokerIntentClaimBytes.__dataclass_fields__
    intent = _intent()
    claim = BrokerIntentClaimBytes(
        ".recover-intent-00000000000000000007-" + intent.nonce + ".json",
        encode_broker_intent(intent),
        IDENTITY,
        recovered=True,
    )
    store = FakeStore(recoveries=[claim])
    resolver = FakeResolver(_plan(intent))
    execution = RecoveryStateExecution(intent, checkpoint=None)

    result = consume_one_broker_intent(
        store,
        resolver,
        execution,
        now_unix_ms=intent.created_at_unix_ms + 1,
    )

    assert result.code is BrokerIntentConsumeCode.SUCCEEDED
    assert resolver.intents == [intent]
    assert execution.execute_attempts == 0
    assert len(execution.resume_calls) == 1
    resumed_intent, resumed_plan, context = execution.resume_calls[0]
    assert resumed_intent == intent
    assert resumed_plan is resolver.plan
    assert getattr(context, "transaction_id") == intent.transaction_id
    assert execution.started_transaction_ids == [intent.transaction_id]
    assert execution.effect_count == 1
    assert store.terminals == [(claim.claim_name, b'{"result":"succeeded"}\n')]
    assert store.releases == [claim.claim_name]


@pytest.mark.parametrize(
    "checkpoint",
    (*BrokerCheckpoint, "after_execution_before_terminal"),
    ids=lambda checkpoint: (
        checkpoint.value if type(checkpoint) is BrokerCheckpoint else checkpoint
    ),
)
def test_recovered_claim_resumes_each_recorded_checkpoint_without_a_second_effect(
    checkpoint: BrokerCheckpoint | str,
) -> None:
    assert "recovered" in BrokerIntentClaimBytes.__dataclass_fields__
    intent = _intent()
    claim = BrokerIntentClaimBytes(
        ".recover-intent-00000000000000000007-" + intent.nonce + ".json",
        encode_broker_intent(intent),
        IDENTITY,
        recovered=True,
    )
    store = FakeStore(recoveries=[claim])
    execution = RecoveryStateExecution(intent, checkpoint=checkpoint, effect_count=1)

    result = consume_one_broker_intent(
        store,
        FakeResolver(_plan(intent)),
        execution,
        now_unix_ms=intent.created_at_unix_ms + 1,
    )

    assert result.code is BrokerIntentConsumeCode.SUCCEEDED
    assert execution.execute_attempts == 0
    assert len(execution.resume_calls) == 1
    assert execution.started_transaction_ids == []
    assert execution.effect_count == 1
    assert store.terminals == [(claim.claim_name, b'{"result":"succeeded"}\n')]


@pytest.mark.parametrize("evidence", ("missing", "contradictory"))
def test_recovered_claim_with_missing_or_contradictory_evidence_is_terminal_blocked_drift(
    evidence: str,
) -> None:
    assert "recovered" in BrokerIntentClaimBytes.__dataclass_fields__
    intent = _intent()
    claim = BrokerIntentClaimBytes(
        ".recover-intent-00000000000000000007-" + intent.nonce + ".json",
        encode_broker_intent(intent),
        IDENTITY,
        recovered=True,
    )
    store = FakeStore(recoveries=[claim])
    execution = RecoveryStateExecution(intent, checkpoint=None, evidence=evidence)

    result = consume_one_broker_intent(
        store,
        FakeResolver(_plan(intent)),
        execution,
        now_unix_ms=intent.created_at_unix_ms + 1,
    )

    assert result.code is BrokerIntentConsumeCode.BLOCKED_DRIFT
    assert execution.execute_attempts == 0
    assert len(execution.resume_calls) == 1
    assert execution.started_transaction_ids == []
    assert execution.effect_count == 0
    assert store.terminals == [(claim.claim_name, b'{"result":"blocked_drift"}\n')]
    assert store.releases == [claim.claim_name]


def test_recovered_claim_releases_its_lease_when_terminalization_fails() -> None:
    assert "recovered" in BrokerIntentClaimBytes.__dataclass_fields__
    intent = _intent()
    claim = BrokerIntentClaimBytes(
        ".recover-intent-00000000000000000007-" + intent.nonce + ".json",
        encode_broker_intent(intent),
        IDENTITY,
        recovered=True,
    )
    store = FakeStore(
        recoveries=[claim], terminal_error=OSError("terminal write unavailable")
    )

    with pytest.raises(BrokerIntentConsumerError) as caught:
        consume_one_broker_intent(
            store,
            FakeResolver(_plan(intent)),
            RecoveryStateExecution(intent, checkpoint=None),
            now_unix_ms=intent.created_at_unix_ms + 1,
        )

    assert caught.value.code is BrokerIntentConsumeCode.TERMINAL_WRITE_FAILED
    assert store.releases == [claim.claim_name]


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


def test_invalid_message_reply_is_terminal_execution_failure_without_restart_retry() -> (
    None
):
    intent = _intent()
    claim = BrokerIntentClaimBytes(
        ".claim-intent-00000000000000000007-" + intent.nonce + ".json",
        encode_broker_intent(intent),
        IDENTITY,
    )
    store = FakeStore([claim])
    execution = FakeExecution(_invalid_message_response(intent))

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


@pytest.mark.parametrize(
    "drift",
    (
        lambda binding: dataclasses.replace(binding, transaction_id="4" * 32),
        lambda binding: dataclasses.replace(
            binding, operation=ChpbTransactionOperation.REPLACE
        ),
        lambda binding: dataclasses.replace(binding, store_uuid="4" * 32),
        lambda binding: dataclasses.replace(
            binding,
            principal=dataclasses.replace(binding.principal, agent_id="bee_2"),
        ),
        lambda binding: dataclasses.replace(
            binding,
            principal=dataclasses.replace(binding.principal, manifest_generation=4),
        ),
        lambda binding: dataclasses.replace(
            binding,
            principal=dataclasses.replace(binding.principal, unit_generation=10),
        ),
        lambda binding: dataclasses.replace(
            binding,
            principal=dataclasses.replace(binding.principal, mcs_pair="c1,c2"),
        ),
        lambda binding: dataclasses.replace(
            binding,
            principal=dataclasses.replace(binding.principal, fencing_epoch=5),
        ),
        lambda binding: dataclasses.replace(
            binding,
            policy=dataclasses.replace(binding.policy, policy_generation=8),
        ),
        lambda binding: dataclasses.replace(
            binding,
            policy=dataclasses.replace(binding.policy, projection_digest="b" * 64),
        ),
    ),
    ids=(
        "transaction_id",
        "operation",
        "store_uuid",
        "principal_agent",
        "principal_manifest",
        "principal_unit",
        "principal_mcs",
        "principal_fencing",
        "policy_generation",
        "policy_projection",
    ),
)
def test_committed_reply_with_foreign_intent_binding_is_terminal_execution_failure(
    drift,
) -> None:
    intent = _intent()
    claim = BrokerIntentClaimBytes(
        ".claim-intent-00000000000000000007-" + intent.nonce + ".json",
        encode_broker_intent(intent),
        IDENTITY,
    )
    store = FakeStore([claim])
    execution = FakeExecution(_response(intent, binding=drift(_binding(intent))))

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


@pytest.mark.parametrize(
    "result",
    (BrokerResultCode.ROLLED_BACK, BrokerResultCode.BLOCKED_DRIFT),
)
def test_noncommitted_terminal_reply_is_terminal_execution_failure(
    result: BrokerResultCode,
) -> None:
    intent = _intent()
    claim = BrokerIntentClaimBytes(
        ".claim-intent-00000000000000000007-" + intent.nonce + ".json",
        encode_broker_intent(intent),
        IDENTITY,
    )
    store = FakeStore([claim])
    execution = FakeExecution(_response(intent, result=result))

    consumed = consume_one_broker_intent(
        store,
        FakeResolver(_plan(intent)),
        execution,
        now_unix_ms=intent.created_at_unix_ms + 1,
    )

    assert consumed.code is BrokerIntentConsumeCode.EXECUTION_FAILED
    assert len(execution.calls) == 1
    assert store.terminals == [(claim.claim_name, b'{"result":"execution_failed"}\n')]


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
        ({76, 76, -1, True, "bad", 77}, [76, 77]),
        (frozenset((78, 78, -1, True, "bad", 79)), [78, 79]),
        ({"fd": 80}, []),
    ),
    ids=("tuple", "list", "set", "frozenset", "other_container"),
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
