from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
import hashlib
import json
from pathlib import Path

import pytest
import codex_master.agent_operations as agent_operations_module

from codex_master.agent_contracts import (
    AgentLeaseV1,
    AgentNoWorkV1,
    AgentPollV1,
    AgentReceiptV1,
    AgentResultV1,
    serialize_agent_result,
)
from codex_master.agent_operations import (
    MAX_AGENT_OPERATION_STATE_BYTES,
    MAX_AGENT_OPERATION_RECORDS,
    AgentAttemptExhaustionV1,
    AgentOperationDeadlineExpiryV1,
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


class SequenceClock:
    def __init__(self, values: tuple[datetime, ...]) -> None:
        self.values = iter(values)
        self.calls = 0

    def __call__(self) -> datetime:
        self.calls += 1
        return next(self.values)


def digest(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def remote_owner_context(action: str) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": 1,
        "owner": "ollama.remote",
        "action": action,
        "host_ref": "worker-one",
        "instance_ref": "ollama-one",
        "registry_generation": 7,
        "ollama_registry_generation": 7,
        "resource_generation": 9,
        "lease_epoch": 3,
        "queue_plan_digest": DIGEST_A,
        "plan_precondition_digest": DIGEST_A,
        "instance": {
            "ref": "ollama-one", "label": "Ollama One", "host_ref": "worker-one",
            "ollama_executable": "/private/ollama", "models_directory": "/private/models",
            "selected_model_refs": ["model-one"], "allowed_cpus": "1", "cpu_quota_percent": 100,
            "cpu_weight": 50, "lifecycle_state": "planned", "readiness_state": "unknown",
        },
    }
    if action != "plan":
        value["plan_id"] = "plan-one"
    return value


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
        {"admin_operation_id": "operation-admin-one", "probe_schema": 1}
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
        **(
            {
                "target_host_ref": "worker-one",
                "required_registry_generation": 7,
                "required_lease_epoch": 3,
                "resource_generation": 9,
                "plan_precondition_digest": DIGEST_A,
                "owner_context": remote_owner_context(action),
            }
            if kind == "ollama.instance"
            else {}
        ),
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
        DIGEST_A if actual_result.kind == "ollama.instance" else None,
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


@pytest.mark.parametrize(
    ("terminal_state", "expected_bindings"),
    (("succeeded", 1), ("failed", 1), ("cancelled", 0)),
)
def test_host_probe_owner_migration_exports_exact_receipts_but_not_cancelled(
    tmp_path: Path,
    terminal_state: str,
    expected_bindings: int,
) -> None:
    store = store_at(tmp_path)
    request = replace(
        operation_request(
            arguments={
                "admin_operation_id": "operation-admin-one",
                "probe_schema": 1,
            }
        ),
        target_host_ref="worker-one",
    )
    queued = store.enqueue(request)
    assert len(store._host_probe_lifecycle_bindings()) == 1

    if terminal_state == "cancelled":
        store.cancel(queued.operation_id)
    else:
        lease = store.poll(principal(), poll())
        assert isinstance(lease, AgentLeaseV1)
        if terminal_state == "succeeded":
            receipt = receipt_for(lease)
        else:
            receipt = receipt_for(
                lease,
                state="failed",
                result=result_for(lease, ready=False),
                reason_codes=("resource_unavailable",),
            )
        store.complete(principal(), receipt)

    assert len(store._host_probe_lifecycle_bindings()) == expected_bindings


def test_host_probe_request_rejects_boolean_schema_before_store_mutation(
    tmp_path: Path,
) -> None:
    store = store_at(tmp_path)
    document = tmp_path / "agent-operations" / "operations.json"
    before = document.read_bytes()

    with pytest.raises(AgentOperationError, match="host.request_invalid"):
        store.enqueue(
            operation_request(
                arguments={
                    "admin_operation_id": "operation-admin-one",
                    "probe_schema": True,
                }
            )
        )

    assert document.read_bytes() == before


def test_default_clock_can_enqueue_without_second_aligned_injection(
    tmp_path: Path,
) -> None:
    store = AgentOperationStore(tmp_path)
    request = operation_request(
        deadline=datetime.now(UTC).replace(microsecond=0) + timedelta(minutes=5)
    )

    assert store.enqueue(request).state == "queued"
    with pytest.raises(AgentOperationError, match="host.request_invalid"):
        operation_request(deadline=NOW.replace(microsecond=1))


def test_expired_lease_redelivers_with_incremented_attempt(tmp_path: Path) -> None:
    clock = Clock()
    store = store_at(tmp_path, clock)
    queued = store.enqueue(operation_request())
    first = store.poll(principal("worker-one"), poll(epoch=3))
    assert isinstance(first, AgentLeaseV1)

    clock.advance(seconds=31)
    second = store.poll(principal("worker-one"), poll(epoch=3))

    assert isinstance(second, AgentLeaseV1)
    assert second.operation_id == queued.operation_id
    assert second.attempt == first.attempt + 1
    assert second.lease_id != first.lease_id


def test_redelivery_uses_current_document_generation_as_exact_lease_fence(
    tmp_path: Path,
) -> None:
    clock = Clock()
    store = store_at(tmp_path, clock)
    store.enqueue(operation_request())
    first = store.poll(principal(), poll(epoch=3))
    assert isinstance(first, AgentLeaseV1)
    clock.advance(seconds=31)
    current_principal = AgentPrincipalV1("worker-one", 8)

    second = store.poll(
        current_principal,
        poll(epoch=3, registry_generation=8),
    )

    assert isinstance(second, AgentLeaseV1)
    assert second.registry_generation == 8
    assert store.context(second.operation_id)["registry_generation"] == 7
    assert store.complete(current_principal, receipt_for(second)).state == "succeeded"


def test_cross_host_or_digest_drift_receipt_changes_nothing(tmp_path: Path) -> None:
    store = store_at(tmp_path)
    lease = lease_one(store)
    before = store.get(lease.operation_id)

    with pytest.raises(AgentOperationError, match="host.identity_mismatch"):
        store.complete(principal("worker-two"), receipt_for(lease))

    assert store.get(lease.operation_id) == before

    drifted = replace(
        lease,
        arguments={
            "admin_operation_id": "operation-admin-other",
            "probe_schema": 1,
        },
        arguments_digest=digest(
            {
                "admin_operation_id": "operation-admin-other",
                "probe_schema": 1,
            }
        ),
    )
    with pytest.raises(AgentOperationError, match="host.arguments_digest_mismatch"):
        store.complete(principal("worker-one"), receipt_for(drifted))

    assert store.get(lease.operation_id) == before


def test_target_host_fence_never_leases_to_another_host(tmp_path: Path) -> None:
    store = store_at(tmp_path)
    request = operation_request()
    request = replace(request, target_host_ref="worker-one")
    store.enqueue(request)

    no_work = store.poll(principal("worker-two"), poll())
    assert isinstance(no_work, AgentNoWorkV1)
    leased = store.poll(principal("worker-one"), poll(epoch=4))
    assert isinstance(leased, AgentLeaseV1)
    assert leased.host_ref == "worker-one"

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

    assert store.poll(principal(), poll(epoch=3)) == AgentNoWorkV1(7, 3, 0)
    with pytest.raises(AgentOperationError, match="host.lease_epoch_stale"):
        store.poll(principal(), poll(epoch=2))


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


def test_completion_validation_exposes_owner_context_without_mutation(
    tmp_path: Path,
) -> None:
    store = store_at(tmp_path)
    request = replace(operation_request(), target_host_ref="worker-one")
    queued = store.enqueue(request)
    lease = store.poll(principal(), poll())
    assert isinstance(lease, AgentLeaseV1)
    receipt = receipt_for(lease)

    context = store.validate_completion(principal(), receipt)

    assert context == {
        "target_host_ref": "worker-one",
        "registry_generation": 7,
        "arguments": request.arguments,
        "required_registry_generation": None,
        "required_lease_epoch": None,
        "resource_generation": None,
        "plan_precondition_digest": None,
        "envelope_digest": None,
    }
    assert store.get(queued.operation_id).state == "leased"
    completed = store.complete(principal(), receipt)
    assert completed.state == "succeeded"
    assert store.validate_completion(principal(), receipt) == context


def test_envelope_lease_epoch_fence_terminalizes_before_a_stale_lease(
    tmp_path: Path,
) -> None:
    store = store_at(tmp_path)
    queued = store.enqueue(
        replace(
            operation_request(kind="ollama.instance", action="plan"),
            target_host_ref="worker-one",
            required_registry_generation=7,
            required_lease_epoch=3,
            resource_generation=9,
            plan_precondition_digest=DIGEST_A,
        )
    )

    no_work = store.poll(principal(), poll(epoch=4))

    assert isinstance(no_work, AgentNoWorkV1)
    terminal = store.get(queued.operation_id)
    assert terminal.state == "failed"
    assert terminal.reason_codes == ("host.lease_epoch_stale",)


@pytest.mark.parametrize(
    ("action", "arguments"),
    (
        ("plan", {"instance_ref": "ollama-one", "generation": 7}),
        ("apply", {"plan_ref": "plan-one"}),
        ("probe", {"instance_ref": "ollama-one", "generation": 7}),
        ("stop", {"instance_ref": "ollama-one", "generation": 7}),
    ),
)
def test_legacy_remote_record_without_v2_envelope_terminalizes_before_lease(
    tmp_path: Path, action: str, arguments: dict[str, object]
) -> None:
    store = store_at(tmp_path)
    request = AgentOperationRequestV1(
        key="legacy-" + action,
        kind="ollama.instance",
        action=action,  # type: ignore[arg-type]
        registry_generation=7,
        plan_digest=DIGEST_A,
        arguments=arguments,
        deadline=NOW + timedelta(minutes=5),
        target_host_ref="worker-one",
        required_registry_generation=7,
        required_lease_epoch=3,
        resource_generation=9,
        plan_precondition_digest=DIGEST_A,
        owner_context=remote_owner_context(action),
    )
    queued = store.enqueue(request)
    with store._state.locked():  # noqa: SLF001 - production-format migration fixture
        document = store._read_locked()  # noqa: SLF001
        record = next(item for item in document["operations"] if item["operation_id"] == queued.operation_id)
        record.pop("envelope_digest")
        store._write_locked(document)  # noqa: SLF001

    restarted = store_at(tmp_path)
    assert isinstance(restarted.poll(principal(), poll()), AgentNoWorkV1)
    terminal = restarted.get(queued.operation_id)
    assert terminal.state == "failed"
    assert terminal.reason_codes == ("host.operation_envelope_stale",)


def test_remote_owner_context_survives_restart_before_index_projection(tmp_path: Path) -> None:
    store = store_at(tmp_path)
    request = AgentOperationRequestV1(
        key="owner-crash-boundary",
        kind="ollama.instance",
        action="plan",
        registry_generation=7,
        plan_digest=DIGEST_A,
        arguments={"instance_ref": "ollama-one", "generation": 7},
        deadline=NOW + timedelta(minutes=5),
        target_host_ref="worker-one",
        required_registry_generation=7,
        required_lease_epoch=3,
        resource_generation=9,
        plan_precondition_digest=DIGEST_A,
        owner_context=remote_owner_context("plan"),
    )
    queued = store.enqueue(request)
    # Simulates the owner-index write failing immediately after enqueue.
    restarted = store_at(tmp_path)
    assert restarted.owner_context(queued.operation_id) == request.owner_context


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


def test_legacy_leased_record_without_lease_generation_remains_loadable(
    tmp_path: Path,
) -> None:
    store = store_at(tmp_path)
    leased = lease_one(store)
    document = tmp_path / "agent-operations" / "operations.json"
    payload = json.loads(document.read_text(encoding="utf-8"))
    payload["operations"][0]["lease"].pop("registry_generation")
    document.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    document.chmod(0o600)

    restarted = store_at(tmp_path)

    assert restarted.get(leased.operation_id).state == "leased"
    assert restarted.complete(principal(), receipt_for(leased)).state == "succeeded"


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

    for attempt in range(1, 9):
        leased = store.poll(principal(), poll(epoch=3))
        assert isinstance(leased, AgentLeaseV1)
        assert leased.attempt == attempt
        clock.advance(seconds=31)

    assert isinstance(store.poll(principal(), poll(epoch=3)), AgentNoWorkV1)
    terminal = store.get(queued.operation_id)
    assert terminal.state == "unknown"
    assert terminal.reason_codes == ("host.attempts_exhausted",)


def test_persisted_attempt_exhaustion_is_discovered_by_same_host_owner(
    tmp_path: Path,
) -> None:
    clock = Clock()
    store = store_at(tmp_path, clock)
    queued = store.enqueue(
        replace(operation_request(), target_host_ref="worker-one")
    )

    for attempt in range(1, 9):
        leased = store.poll(principal(), poll(epoch=3))
        assert isinstance(leased, AgentLeaseV1)
        assert leased.attempt == attempt
        clock.advance(seconds=31)
    store.expire_leases()
    persisted = store.get(queued.operation_id)
    assert persisted.state == "unknown"
    assert persisted.reason_codes == ("host.attempts_exhausted",)

    observed: list[object] = []

    def reconcile(context: object) -> bool:
        observed.append(context)
        assert store.get(queued.operation_id) == persisted
        return True

    restarted = store_at(tmp_path, clock)
    assert isinstance(
        restarted.poll(
            principal(),
            poll(epoch=3),
            attempt_exhaustion_owner=reconcile,
        ),
        AgentNoWorkV1,
    )
    assert isinstance(
        restarted.poll(
            principal(),
            poll(epoch=3),
            attempt_exhaustion_owner=reconcile,
        ),
        AgentNoWorkV1,
    )
    assert len(observed) == 1
    assert restarted.get(queued.operation_id) == persisted


def test_operation_deadline_never_issues_a_new_lease_and_orders_owner_first(
    tmp_path: Path,
) -> None:
    clock = Clock()
    store = store_at(tmp_path, clock)
    queued = store.enqueue(
        replace(
            operation_request(deadline=NOW + timedelta(minutes=5)),
            target_host_ref="worker-one",
        )
    )
    first = store.poll(principal(), poll(epoch=3))
    assert isinstance(first, AgentLeaseV1)
    clock.advance(seconds=301)
    observed: list[object] = []

    def reconcile(context: object) -> bool:
        observed.append(context)
        assert store.get(queued.operation_id).state == "leased"
        return True

    idle = store.poll(
        principal(),
        poll(epoch=3),
        operation_deadline_owner=reconcile,
    )

    assert isinstance(idle, AgentNoWorkV1)
    assert len(observed) == 1
    terminal = store.get(queued.operation_id)
    assert terminal.attempt == 1
    assert terminal.state == "unknown"
    assert terminal.reason_codes == ("host.lease_expired",)


def test_lease_is_capped_at_operation_deadline_and_predeadline_completion_works(
    tmp_path: Path,
) -> None:
    clock = Clock()
    store = store_at(tmp_path, clock)
    operation_deadline = NOW + timedelta(minutes=5)
    store.enqueue(operation_request(deadline=operation_deadline))
    clock.now = operation_deadline - timedelta(seconds=1)

    lease = store.poll(principal(), poll(epoch=3))

    assert isinstance(lease, AgentLeaseV1)
    assert lease.deadline == operation_deadline
    assert store.complete(principal(), receipt_for(lease)).state == "succeeded"


def test_poll_uses_one_now_per_locked_transition_at_deadline_boundary(
    tmp_path: Path,
) -> None:
    operation_deadline = NOW + timedelta(minutes=5)
    clock = SequenceClock(
        (
            NOW,
            operation_deadline - timedelta(seconds=1),
            operation_deadline - timedelta(seconds=1),
        )
    )
    store = AgentOperationStore.for_test(tmp_path, clock=clock)
    store.enqueue(operation_request(deadline=operation_deadline))

    lease = store.poll(principal(), poll(epoch=3))

    assert isinstance(lease, AgentLeaseV1)
    assert lease.deadline == operation_deadline
    assert clock.calls == 3


def test_poll_at_operation_deadline_never_issues_a_lease(tmp_path: Path) -> None:
    clock = Clock()
    store = store_at(tmp_path, clock)
    operation_deadline = NOW + timedelta(minutes=5)
    queued = store.enqueue(operation_request(deadline=operation_deadline))
    clock.now = operation_deadline

    result = store.poll(principal(), poll(epoch=3))

    assert isinstance(result, AgentNoWorkV1)
    terminal = store.get(queued.operation_id)
    assert terminal.state == "unknown"
    assert terminal.attempt == 0
    assert terminal.reason_codes == ("host.lease_expired",)


def test_completion_after_operation_deadline_is_stale_even_with_live_lease(
    tmp_path: Path,
) -> None:
    clock = Clock()
    store = store_at(tmp_path, clock)
    operation_deadline = NOW + timedelta(minutes=5)
    store.enqueue(operation_request(deadline=operation_deadline))
    clock.now = operation_deadline - timedelta(seconds=1)
    lease = store.poll(principal(), poll(epoch=3))
    assert isinstance(lease, AgentLeaseV1)
    before = store.get(lease.operation_id)
    clock.now = operation_deadline + timedelta(seconds=1)

    with pytest.raises(AgentOperationError, match="host.lease_stale"):
        store.complete(principal(), receipt_for(lease))

    assert store.get(lease.operation_id) == before


def test_persisted_overlong_lease_terminalizes_at_operation_deadline(
    tmp_path: Path,
) -> None:
    clock = Clock()
    store = store_at(tmp_path, clock)
    operation_deadline = NOW + timedelta(minutes=5)
    store.enqueue(operation_request(deadline=operation_deadline))
    clock.now = operation_deadline - timedelta(seconds=1)
    lease = store.poll(principal(), poll(epoch=3))
    assert isinstance(lease, AgentLeaseV1)
    document_path = tmp_path / "agent-operations" / "operations.json"
    document = json.loads(document_path.read_text(encoding="utf-8"))
    document["operations"][0]["lease"]["deadline"] = (
        operation_deadline + timedelta(seconds=29)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    document_path.write_text(
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    document_path.chmod(0o600)
    clock.now = operation_deadline
    restarted = store_at(tmp_path, clock)
    observed: list[object] = []

    restarted.expire_leases(
        operation_deadline_owner=lambda context: observed.append(context) is None,
        owner_host_ref="worker-one",
    )

    assert len(observed) == 1
    terminal = restarted.get(lease.operation_id)
    assert terminal.state == "unknown"
    assert terminal.reason_codes == ("host.lease_expired",)


def test_ownerless_poll_terminalizes_queued_operation_deadline(
    tmp_path: Path,
) -> None:
    clock = Clock()
    store = store_at(tmp_path, clock)
    queued = store.enqueue(
        operation_request(deadline=NOW + timedelta(minutes=5))
    )
    clock.advance(seconds=301)

    assert isinstance(store.poll(principal(), poll(epoch=3)), AgentNoWorkV1)
    terminal = store.get(queued.operation_id)
    assert terminal.attempt == 0
    assert terminal.state == "unknown"
    assert terminal.reason_codes == ("host.lease_expired",)


def test_mixed_lifecycle_candidates_share_budget_scope_and_ack_after_durable_write(
    tmp_path: Path,
) -> None:
    clock = Clock()
    store = store_at(tmp_path, clock)
    operation_ids: list[str] = []
    for index in range(10):
        deadline = NOW + timedelta(minutes=15 if index % 2 == 0 else 5)
        operation_ids.append(
            store.enqueue(
                replace(
                    operation_request(
                        deadline=deadline,
                        key=f"mixed-lifecycle-{index}",
                    ),
                    target_host_ref="worker-one",
                )
            ).operation_id
        )
    wrong_host = store.enqueue(
        replace(
            operation_request(
                deadline=NOW + timedelta(minutes=5),
                key="mixed-lifecycle-wrong-host",
            ),
            target_host_ref="worker-two",
        )
    )
    document_path = tmp_path / "agent-operations" / "operations.json"
    document = json.loads(document_path.read_text(encoding="utf-8"))
    for index, record in enumerate(document["operations"][:10]):
        if index % 2:
            continue
        record["state"] = "leased"
        record["attempt"] = 8
        record["lease"] = {
            "lease_id": f"lease-mixed-{index}",
            "host_ref": "worker-one",
            "registry_generation": 7,
            "lease_epoch": 3,
            "deadline": (NOW + timedelta(minutes=1)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
        }
    document_path.write_text(
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    document_path.chmod(0o600)
    record_fields = {
        record["operation_id"]: frozenset(record) for record in document["operations"]
    }
    clock.now = NOW + timedelta(minutes=6)
    restarted = store_at(tmp_path, clock)
    offered: list[object] = []
    acknowledged: list[str] = []

    def owner(context: object) -> bool:
        offered.append(context)
        return True

    def acknowledge(context: object) -> None:
        assert isinstance(
            context,
            (AgentAttemptExhaustionV1, AgentOperationDeadlineExpiryV1),
        )
        terminal = restarted.get(context.operation_id)
        assert terminal.state == "unknown"
        acknowledged.append(context.operation_id)

    restarted.expire_leases(
        attempt_exhaustion_owner=owner,
        operation_deadline_owner=owner,
        lifecycle_ack_owner=acknowledge,
        owner_host_ref="worker-one",
    )

    assert len(offered) == len(acknowledged) == 8
    assert any(isinstance(item, AgentAttemptExhaustionV1) for item in offered)
    assert any(isinstance(item, AgentOperationDeadlineExpiryV1) for item in offered)
    assert restarted.get(wrong_host.operation_id).state == "queued"

    restarted.expire_leases(
        attempt_exhaustion_owner=owner,
        operation_deadline_owner=owner,
        lifecycle_ack_owner=acknowledge,
        owner_host_ref="worker-one",
    )
    assert len(offered) == len(acknowledged) == 10
    assert {restarted.get(operation_id).state for operation_id in operation_ids} == {
        "unknown"
    }
    durable = document_path.read_bytes()
    persisted = json.loads(durable)
    assert persisted["schema_version"] == 1
    assert len(durable) <= MAX_AGENT_OPERATION_STATE_BYTES
    assert {
        record["operation_id"]: frozenset(record)
        for record in persisted["operations"]
    } == record_fields


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


def test_large_result_completion_survives_document_pressure_replay_and_restart(
    tmp_path: Path, monkeypatch
) -> None:
    store = store_at(tmp_path)
    lease = lease_one(store)
    result = AgentResultV1(
        "host.probe",
        "collect",
        {"data": "x" * (250 * 1024)},
    )
    receipt = receipt_for(lease, result=result)
    document_path = tmp_path / "agent-operations" / "operations.json"
    constrained_limit = len(document_path.read_bytes()) + 2048
    monkeypatch.setattr(
        agent_operations_module,
        "MAX_AGENT_OPERATION_STATE_BYTES",
        constrained_limit,
    )

    completed = store.complete(principal(), receipt)
    replayed = store.complete(principal(), receipt)
    restarted = store_at(tmp_path)

    assert completed == replayed
    assert len(document_path.read_bytes()) <= constrained_limit
    assert restarted.result(lease.operation_id) == result


def test_completion_at_exhausted_metadata_bound_leaves_no_result_sidecar(
    tmp_path: Path, monkeypatch
) -> None:
    store = store_at(tmp_path)
    lease = lease_one(store)
    document_path = tmp_path / "agent-operations" / "operations.json"
    result_path = tmp_path / "agent-operations" / "results" / lease.operation_id
    before = document_path.read_bytes()
    monkeypatch.setattr(
        agent_operations_module,
        "MAX_AGENT_OPERATION_STATE_BYTES",
        len(before),
    )

    with pytest.raises(
        AgentOperationError, match="host.operation_store_unavailable"
    ):
        store.complete(principal(), receipt_for(lease))

    assert document_path.read_bytes() == before
    assert not result_path.exists()


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
