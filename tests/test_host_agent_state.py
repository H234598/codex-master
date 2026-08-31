from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path

import pytest

from codex_master.agent_contracts import AgentLeaseV1, AgentResultV1
from codex_master.host_agent_state import HostAgentState, HostAgentStateError


def digest(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def lease(**changes: object) -> AgentLeaseV1:
    arguments = changes.pop("arguments", {"probe_profile": "basic"})
    values: dict[str, object] = {
        "operation_id": "operation-one",
        "lease_id": "lease-one",
        "host_ref": "worker-one",
        "kind": "host.probe",
        "action": "collect",
        "registry_generation": 7,
        "lease_epoch": 3,
        "attempt": 1,
        "plan_digest": "sha256:" + "a" * 64,
        "arguments_digest": digest(arguments),
        "deadline": datetime(2099, 1, 1, tzinfo=UTC),
        "arguments": arguments,
    }
    values.update(changes)
    return AgentLeaseV1(**values)  # type: ignore[arg-type]


def result(value: AgentLeaseV1) -> AgentResultV1:
    return AgentResultV1(value.kind, value.action, {"status": "complete"})


def test_effect_started_without_receipt_recovers_unknown(tmp_path: Path) -> None:
    state = HostAgentState.for_test(tmp_path, host_ref="worker-one")
    item = lease(
        kind="ollama.instance",
        action="apply",
        arguments={"plan_ref": "plan-one"},
        arguments_digest=digest({"plan_ref": "plan-one"}),
    )
    assert state.accept(item) is None
    state.begin_effect(item)
    recovered = HostAgentState.for_test(tmp_path, host_ref="worker-one").recover(item)
    assert recovered is not None and recovered.state == "unknown"


def test_pre_effect_crash_redelivers_and_finished_receipt_replays(
    tmp_path: Path,
) -> None:
    item = lease()
    state = HostAgentState.for_test(tmp_path, host_ref="worker-one")
    state.accept(item)
    restarted = HostAgentState.for_test(tmp_path, host_ref="worker-one")
    assert restarted.recover(item) is None
    receipt = restarted.finish(
        item,
        state="succeeded",
        reason_codes=("host.probe_complete",),
        result=result(item),
    )
    assert restarted.accept(item) == receipt


def test_recover_returns_receipt_completed_between_its_locked_reads(
    tmp_path: Path,
) -> None:
    item = lease()

    class RacingState(HostAgentState):
        raced = False

        def accept(self, value: AgentLeaseV1):  # type: ignore[no-untyped-def]
            saved = super().accept(value)
            if saved is None and not self.raced:
                self.raced = True
                self.finish(
                    value,
                    state="succeeded",
                    reason_codes=("host.probe_complete",),
                    result=result(value),
                )
            return saved

    state = RacingState.for_test(tmp_path, host_ref="worker-one")
    recovered = state.recover(item)
    assert recovered is not None and recovered.state == "succeeded"


def test_wrong_host_stale_epoch_and_digest_conflict_fail_closed(tmp_path: Path) -> None:
    state = HostAgentState.for_test(tmp_path, host_ref="worker-one")
    state.accept(lease(operation_id="new", lease_epoch=4))
    with pytest.raises(HostAgentStateError, match="host.identity_mismatch"):
        state.accept(lease(host_ref="worker-two", operation_id="wrong"))
    with pytest.raises(HostAgentStateError, match="host.lease_epoch_stale"):
        state.accept(lease(operation_id="old", lease_epoch=3))
    original = lease(operation_id="same", lease_epoch=4)
    state.accept(original)
    with pytest.raises(HostAgentStateError, match="host.replay_conflict"):
        state.accept(
            lease(operation_id="same", lease_epoch=4, plan_digest="sha256:" + "b" * 64)
        )


def test_receipts_are_bounded_and_only_older_generations_are_pruned(
    tmp_path: Path,
) -> None:
    state = HostAgentState.for_test(tmp_path, host_ref="worker-one", max_receipts=2)
    for number, generation in ((1, 7), (2, 7)):
        item = lease(
            operation_id=f"operation-{number}",
            lease_id=f"lease-{number}",
            registry_generation=generation,
        )
        state.accept(item)
        state.finish(
            item, state="succeeded", reason_codes=("done",), result=result(item)
        )
    with pytest.raises(HostAgentStateError, match="host.receipt_limit"):
        state.accept(lease(operation_id="operation-3", registry_generation=7))
    newer = lease(operation_id="operation-3", registry_generation=8)
    state.accept(newer)
    state.finish(newer, state="succeeded", reason_codes=("done",), result=result(newer))
    assert state.receipt_count() == 2
    with pytest.raises(HostAgentStateError, match="host.registry_generation_stale"):
        state.accept(
            lease(
                operation_id="operation-1",
                lease_id="lease-reused",
                registry_generation=7,
                lease_epoch=4,
            )
        )
