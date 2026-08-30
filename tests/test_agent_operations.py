from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
import hashlib
import json
from pathlib import Path

import pytest

from codex_master.agent_contracts import (
    AgentLeaseV1,
    AgentNoWorkV1,
    AgentPollV1,
    AgentReceiptV1,
    AgentResultV1,
    serialize_agent_result,
)
from codex_master.agent_operations import (
    MAX_AGENT_OPERATION_RECORDS,
    AgentOperationError,
    AgentOperationRequestV1,
    AgentOperationStore,
    AgentOperationViewV1,
    AgentPrincipalV1,
)


NOW = datetime(2026, 8, 30, 12, 0, 0, tzinfo=UTC)
DIGEST_A = "sha256:" + "a" * 64
CAPABILITIES = "sha256:" + "c" * 64


class Clock:
    def __init__(self) -> None:
        self.now = NOW

    def __call__(self) -> datetime:
        return self.now

    def advance(self, *, seconds: int) -> None:
        self.now += timedelta(seconds=seconds)


def digest(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def store_at(tmp_path: Path, clock: Clock | None = None) -> AgentOperationStore:
    return AgentOperationStore.for_test(tmp_path, clock=clock or Clock())


def principal(host_ref: str = "worker-one") -> AgentPrincipalV1:
    return AgentPrincipalV1(host_ref, 7)


def poll(*, epoch: int = 3, registry_generation: int = 7) -> AgentPollV1:
    return AgentPollV1(registry_generation, epoch, CAPABILITIES, 0)


def operation_request(
    kind: str = "host.probe",
    action: str = "collect",
    *,
    arguments: dict[str, object] | None = None,
    deadline: datetime | None = None,
    key: str = "request-one",
) -> AgentOperationRequestV1:
    payload = (
        {"probe_profile": "quiescence", "include_metrics": True}
        if arguments is None
        else arguments
    )
    return AgentOperationRequestV1(
        key=key,
        kind=kind,
        action=action,
        registry_generation=7,
        plan_digest=DIGEST_A,
        arguments=payload,
        deadline=deadline or NOW + timedelta(minutes=15),
    )


def lease_one(store: AgentOperationStore) -> AgentLeaseV1:
    store.enqueue(operation_request())
    leased = store.poll(principal(), poll())
    assert isinstance(leased, AgentLeaseV1)
    return leased


def result_for(lease: AgentLeaseV1, **payload: object) -> AgentResultV1:
    return AgentResultV1(
        lease.kind,
        lease.action,
        {
            "ready": True,
            "observed_at": "2026-08-30T12:00:00Z",
            **payload,
        },
    )


def receipt_for(
    lease: AgentLeaseV1,
    *,
    state: str = "succeeded",
    result: AgentResultV1 | None = None,
    reason_codes: tuple[str, ...] = ("resource_ready",),
) -> AgentReceiptV1:
    actual_result = result or result_for(lease)
    return AgentReceiptV1(
        lease.operation_id,
        lease.lease_id,
        lease.lease_epoch,
        lease.attempt,
        lease.plan_digest,
        lease.arguments_digest,
        state,  # type: ignore[arg-type]
        reason_codes,
        digest(serialize_agent_result(actual_result)),
        actual_result,
    )


def test_operation_views_and_requests_are_frozen_and_constructible(
    tmp_path: Path,
) -> None:
    request = operation_request()
    view = store_at(tmp_path).enqueue(request)

    assert isinstance(view, AgentOperationViewV1)
    assert view.state == "queued"
    assert view.kind == request.kind
    with pytest.raises(FrozenInstanceError):
        view.state = "failed"  # type: ignore[misc]


def test_expired_lease_redelivers_with_incremented_attempt(tmp_path: Path) -> None:
    clock = Clock()
    store = store_at(tmp_path, clock)
    queued = store.enqueue(operation_request())
    first = store.poll(principal("worker-one"), poll(epoch=3))
    assert isinstance(first, AgentLeaseV1)

    clock.advance(seconds=31)
    assert store.expire_leases() == (queued.operation_id,)
    second = store.poll(principal("worker-one"), poll(epoch=4))

    assert isinstance(second, AgentLeaseV1)
    assert second.operation_id == queued.operation_id
    assert second.attempt == first.attempt + 1
    assert second.lease_id != first.lease_id


def test_cross_host_or_digest_drift_receipt_changes_nothing(tmp_path: Path) -> None:
    store = store_at(tmp_path)
    lease = lease_one(store)
    before = store.get(lease.operation_id)

    with pytest.raises(AgentOperationError, match="host.identity_mismatch"):
        store.complete(principal("worker-two"), receipt_for(lease))

    assert store.get(lease.operation_id) == before

    drifted = replace(
        lease,
        arguments={"probe_profile": "other"},
        arguments_digest=digest({"probe_profile": "other"}),
    )
    with pytest.raises(AgentOperationError, match="host.arguments_digest_mismatch"):
        store.complete(principal("worker-one"), receipt_for(drifted))

    assert store.get(lease.operation_id) == before


def test_queue_limit_is_1024_records(tmp_path: Path) -> None:
    store = store_at(tmp_path)
    for index in range(MAX_AGENT_OPERATION_RECORDS):
        store.enqueue(operation_request(key=f"request-{index}"))

    with pytest.raises(AgentOperationError, match="host.operation_limit"):
        store.enqueue(operation_request(key="request-over-limit"))


def test_enqueue_idempotent_retry_at_capacity_returns_existing_view(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import codex_master.agent_operations as operations

    monkeypatch.setattr(operations, "MAX_AGENT_OPERATION_RECORDS", 2)
    store = store_at(tmp_path)
    first = store.enqueue(operation_request(key="request-one"))
    store.enqueue(operation_request(key="request-two"))

    assert store.enqueue(operation_request(key="request-one")) == first
    with pytest.raises(AgentOperationError, match="host.operation_limit"):
        store.enqueue(operation_request(key="request-three"))


def test_poll_no_work_and_monotone_epoch(tmp_path: Path) -> None:
    store = store_at(tmp_path)

    first = store.poll(principal(), poll(epoch=3))
    assert first == AgentNoWorkV1(7, 3, 0)

    with pytest.raises(AgentOperationError, match="host.lease_epoch_stale"):
        store.poll(principal(), poll(epoch=3))


def test_only_one_active_poll_connection_per_host(tmp_path: Path) -> None:
    store = store_at(tmp_path)
    store._active_polls.add("worker-one")  # type: ignore[attr-defined]

    with pytest.raises(AgentOperationError, match="host.poll_already_active"):
        store.poll(principal(), poll(epoch=3))


def test_poll_rejects_stale_registry_generation(tmp_path: Path) -> None:
    store = store_at(tmp_path)
    store.enqueue(operation_request())

    with pytest.raises(AgentOperationError, match="host.registry_generation_stale"):
        store.poll(principal(), poll(registry_generation=6))


def test_stale_lease_completion_changes_nothing(tmp_path: Path) -> None:
    clock = Clock()
    store = store_at(tmp_path, clock)
    old_lease = lease_one(store)
    clock.advance(seconds=31)
    store.expire_leases()
    new_lease = store.poll(principal(), poll(epoch=4))
    assert isinstance(new_lease, AgentLeaseV1)
    before = store.get(old_lease.operation_id)

    with pytest.raises(AgentOperationError, match="host.lease_stale"):
        store.complete(principal(), receipt_for(old_lease))

    assert store.get(old_lease.operation_id) == before


def test_repeated_completion_is_idempotent_but_conflict_is_rejected(
    tmp_path: Path,
) -> None:
    store = store_at(tmp_path)
    lease = lease_one(store)
    receipt = receipt_for(lease)

    completed = store.complete(principal(), receipt)
    assert completed.state == "succeeded"
    assert store.complete(principal(), receipt) == completed

    conflict = receipt_for(
        lease,
        state="failed",
        result=result_for(lease, ready=False),
        reason_codes=("resource_unavailable",),
    )
    with pytest.raises(AgentOperationError, match="host.completion_conflict"):
        store.complete(principal(), conflict)

    assert store.get(lease.operation_id) == completed


def test_terminal_completion_replay_validates_original_lease_fences(
    tmp_path: Path,
) -> None:
    store = store_at(tmp_path)
    lease = lease_one(store)
    receipt = receipt_for(lease)
    completed = store.complete(principal(), receipt)
    forged = AgentReceiptV1(
        receipt.operation_id,
        "lease-forged",
        receipt.lease_epoch,
        receipt.attempt,
        receipt.plan_digest,
        receipt.arguments_digest,
        receipt.state,
        receipt.reason_codes,
        receipt.result_digest,
        receipt.result,
    )

    with pytest.raises(AgentOperationError, match="host.identity_mismatch"):
        store.complete(principal("worker-two"), receipt)
    with pytest.raises(AgentOperationError, match="host.lease_stale"):
        store.complete(principal(), forged)

    assert store.get(lease.operation_id) == completed


def test_completion_after_durable_lease_deadline_is_stale(
    tmp_path: Path,
) -> None:
    clock = Clock()
    store = store_at(tmp_path, clock)
    lease = lease_one(store)
    before = store.get(lease.operation_id)
    clock.advance(seconds=31)

    with pytest.raises(AgentOperationError, match="host.lease_stale"):
        store.complete(principal(), receipt_for(lease))

    assert store.get(lease.operation_id) == before


def test_receipt_result_kind_action_must_match_operation_before_mutation(
    tmp_path: Path,
) -> None:
    store = store_at(tmp_path)
    lease = lease_one(store)
    before = store.get(lease.operation_id)
    mismatched_result = AgentResultV1(
        "ollama.instance",
        "probe",
        {"ready": True, "instance_ref": "ollama-main"},
    )

    with pytest.raises(AgentOperationError, match="host.result_mismatch"):
        store.complete(principal(), receipt_for(lease, result=mismatched_result))

    assert store.get(lease.operation_id) == before


def test_master_restart_recovers_queued_and_leased_operations(tmp_path: Path) -> None:
    store = store_at(tmp_path)
    store.enqueue(operation_request(key="leased"))
    queued = store.enqueue(operation_request(key="queued"))
    leased = store.poll(principal(), poll(epoch=3))
    assert isinstance(leased, AgentLeaseV1)

    restarted = store_at(tmp_path)

    assert restarted.get(queued.operation_id).state == "queued"
    assert restarted.get(leased.operation_id).state == "leased"


def test_unknown_completion_is_terminal(tmp_path: Path) -> None:
    store = store_at(tmp_path)
    lease = lease_one(store)

    completed = store.complete(
        principal(),
        receipt_for(
            lease,
            state="unknown",
            result=result_for(lease, ready=False),
            reason_codes=("resource_unknown",),
        ),
    )

    assert completed.state == "unknown"
    assert isinstance(store.poll(principal(), poll(epoch=4)), AgentNoWorkV1)


def test_attempt_limit_transitions_expired_operation_to_unknown(
    tmp_path: Path,
) -> None:
    clock = Clock()
    store = store_at(tmp_path, clock)
    queued = store.enqueue(operation_request())

    for epoch in range(3, 11):
        leased = store.poll(principal(), poll(epoch=epoch))
        assert isinstance(leased, AgentLeaseV1)
        assert leased.attempt == epoch - 2
        clock.advance(seconds=31)
        assert store.expire_leases() == (queued.operation_id,)

    assert store.get(queued.operation_id).state == "unknown"
    assert isinstance(store.poll(principal(), poll(epoch=11)), AgentNoWorkV1)


def test_recursive_private_result_fields_are_rejected(tmp_path: Path) -> None:
    store = store_at(tmp_path)
    lease = lease_one(store)

    with pytest.raises(ValueError, match="agent.request_invalid|host.request_invalid"):
        receipt_for(
            lease,
            result=AgentResultV1(
                "host.probe",
                "collect",
                {"nested": {"absolute_path": "/secret"}},
            ),
        )


def test_cancel_queued_is_terminal_and_never_polled_or_redelivered(
    tmp_path: Path,
) -> None:
    clock = Clock()
    store = store_at(tmp_path, clock)
    queued = store.enqueue(operation_request())

    cancelled = store.cancel(queued.operation_id)
    assert cancelled.state == "cancelled"
    assert store.cancel(queued.operation_id) == cancelled
    assert isinstance(store.poll(principal(), poll(epoch=3)), AgentNoWorkV1)
    clock.advance(seconds=31)
    assert store.expire_leases() == ()
    assert store.get(queued.operation_id).state == "cancelled"


def test_cancel_leased_and_terminal_operations_changes_nothing(
    tmp_path: Path,
) -> None:
    store = store_at(tmp_path)
    leased = lease_one(store)
    before_leased = store.get(leased.operation_id)

    with pytest.raises(AgentOperationError, match="host.cancel_conflict"):
        store.cancel(leased.operation_id)
    assert store.get(leased.operation_id) == before_leased

    done = store.complete(principal(), receipt_for(leased))
    with pytest.raises(AgentOperationError, match="host.cancel_conflict"):
        store.cancel(done.operation_id)
    assert store.get(done.operation_id) == done


def test_queue_deadline_and_request_fields_are_bounded(tmp_path: Path) -> None:
    store = store_at(tmp_path)

    with pytest.raises(AgentOperationError, match="host.deadline_invalid"):
        store.enqueue(operation_request(deadline=NOW + timedelta(minutes=16)))
    with pytest.raises(AgentOperationError, match="host.request_invalid"):
        store.enqueue(operation_request(arguments={"nested": {"token_file": "x"}}))
