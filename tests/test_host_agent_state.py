from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
import json
import multiprocessing
from pathlib import Path
import threading

import pytest

from codex_master import host_agent_state
from codex_master.agent_contracts import AgentLeaseV1, AgentResultV1, remote_envelope_digest
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
    if values["kind"] == "ollama.instance":
        values.setdefault("plan_precondition_digest", "sha256:" + "a" * 64)
        values.setdefault("resource_generation", 9)
        values.setdefault(
            "envelope_digest",
            remote_envelope_digest(
                registry_generation=values["registry_generation"],  # type: ignore[arg-type]
                lease_epoch=values["lease_epoch"],  # type: ignore[arg-type]
                resource_generation=values["resource_generation"],  # type: ignore[arg-type]
                plan_precondition_digest=values["plan_precondition_digest"],  # type: ignore[arg-type]
            ),
        )
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
    thread = threading.Thread(target=lambda: state.begin_effect(item))
    thread.start()
    thread.join(2)
    assert not thread.is_alive()
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


@pytest.mark.parametrize(
    ("terminal_state", "reason"),
    (
        ("succeeded", "host.probe_complete"),
        ("unknown", "host.operation_unknown"),
    ),
)
def test_terminal_semantic_receipt_rebinds_to_later_lease_without_new_effect(
    tmp_path: Path, terminal_state: str, reason: str
) -> None:
    state = HostAgentState.for_test(tmp_path, host_ref="worker-one")
    first = lease()
    state.accept(first)
    saved = state.finish(
        first,
        state=terminal_state,  # type: ignore[arg-type]
        reason_codes=(reason,),
        result=result(first),
    )
    later = lease(lease_id="lease-two", attempt=2, registry_generation=8)

    rebound = HostAgentState.for_test(
        tmp_path, host_ref="worker-one"
    ).recover(later)

    assert rebound is not None
    assert rebound.lease_id == later.lease_id
    assert rebound.attempt == later.attempt
    assert rebound.result == saved.result
    assert rebound.result_digest == saved.result_digest
    assert HostAgentState.for_test(
        tmp_path, host_ref="worker-one"
    ).recover(later) == rebound
    with pytest.raises(HostAgentStateError, match="host.replay_conflict"):
        state.recover(
            lease(
                lease_id="lease-three",
                attempt=3,
                registry_generation=8,
                plan_digest="sha256:" + "b" * 64,
            )
        )


def test_expired_unclaimed_same_operation_rebinds_only_safe_fence(
    tmp_path: Path,
) -> None:
    state = HostAgentState.for_test(tmp_path, host_ref="worker-one")
    old = lease(deadline=datetime(2020, 1, 1, tzinfo=UTC))
    state.accept(old)
    renewed = lease(lease_id="lease-two", attempt=2)
    assert state.accept(renewed) is None
    assert state.begin_effect(renewed) is not None
    with pytest.raises(HostAgentStateError, match="host.replay_conflict"):
        state.accept(lease(lease_id="lease-three", attempt=3))


@pytest.mark.parametrize("changed", ("resource_generation", "plan_precondition_digest"))
def test_remote_rebind_refuses_changed_envelope_fence(
    tmp_path: Path, changed: str
) -> None:
    state = HostAgentState.for_test(tmp_path, host_ref="worker-one")
    old = lease(
        kind="ollama.instance", action="apply", arguments={"plan_ref": "plan-one"},
        arguments_digest=digest({"plan_ref": "plan-one"}),
        deadline=datetime(2020, 1, 1, tzinfo=UTC),
    )
    state.accept(old)
    values: dict[str, object] = {"lease_id": "lease-two", "attempt": 2}
    values[changed] = 10 if changed == "resource_generation" else "sha256:" + "b" * 64
    values["envelope_digest"] = remote_envelope_digest(
        registry_generation=old.registry_generation,
        lease_epoch=old.lease_epoch,
        resource_generation=values.get("resource_generation", old.resource_generation),  # type: ignore[arg-type]
        plan_precondition_digest=values.get("plan_precondition_digest", old.plan_precondition_digest),  # type: ignore[arg-type]
    )
    with pytest.raises(HostAgentStateError, match="host.replay_conflict"):
        state.accept(lease(
            kind="ollama.instance", action="apply", arguments={"plan_ref": "plan-one"},
            arguments_digest=digest({"plan_ref": "plan-one"}), **values,
        ))


@pytest.mark.parametrize("changed", ("resource_generation", "plan_precondition_digest"))
def test_remote_terminal_rebind_refuses_changed_envelope_fence(
    tmp_path: Path, changed: str
) -> None:
    state = HostAgentState.for_test(tmp_path, host_ref="worker-one")
    old = lease(
        kind="ollama.instance", action="apply", arguments={"plan_ref": "plan-one"},
        arguments_digest=digest({"plan_ref": "plan-one"}),
    )
    state.accept(old)
    state.finish(
        old,
        state="succeeded",
        reason_codes=("host.operation_succeeded",),
        result=result(old),
    )
    values: dict[str, object] = {"lease_id": "lease-two", "attempt": 2}
    values[changed] = 10 if changed == "resource_generation" else "sha256:" + "b" * 64
    values["envelope_digest"] = remote_envelope_digest(
        registry_generation=old.registry_generation,
        lease_epoch=old.lease_epoch,
        resource_generation=values.get("resource_generation", old.resource_generation),  # type: ignore[arg-type]
        plan_precondition_digest=values.get("plan_precondition_digest", old.plan_precondition_digest),  # type: ignore[arg-type]
    )
    with pytest.raises(HostAgentStateError, match="host.replay_conflict"):
        state.recover(
            lease(
                kind="ollama.instance", action="apply",
                arguments={"plan_ref": "plan-one"},
                arguments_digest=digest({"plan_ref": "plan-one"}), **values,
            )
        )


def test_v3_remote_state_is_refused_while_v1_host_probe_replays(tmp_path: Path) -> None:
    state = HostAgentState.for_test(tmp_path, host_ref="worker-one")
    probe = lease()
    state.accept(probe)
    saved = state.finish(
        probe,
        state="succeeded",
        reason_codes=("host.probe_complete",),
        result=result(probe),
    )
    remote = lease(
        operation_id="operation-remote", kind="ollama.instance", action="apply",
        arguments={"plan_ref": "plan-one"}, arguments_digest=digest({"plan_ref": "plan-one"}),
    )
    state.accept(remote)
    with state._state.locked():  # noqa: SLF001 - production-format V3 fixture
        document = state._read_locked()  # noqa: SLF001
        document["schema_version"] = 3
        document["receipts"][probe.operation_id]["fence"] = document["receipts"][probe.operation_id]["fence"][:10]
        legacy = document["accepted"][remote.operation_id]
        legacy["fence"] = legacy["fence"][:10]
        legacy["lease"]["schema_version"] = 1
        legacy["lease"].pop("plan_precondition_digest")
        legacy["lease"].pop("resource_generation")
        legacy["lease"].pop("envelope_digest")
        state._write_locked(document)  # noqa: SLF001

    restarted = HostAgentState.for_test(tmp_path, host_ref="worker-one")
    assert restarted.recover(probe) == saved
    assert restarted.receipt_count() == 1


def test_live_claim_deadline_terminalizes_unknown_and_late_finish_replays(
    tmp_path: Path,
) -> None:
    item = lease(
        deadline=datetime.now(UTC).replace(microsecond=0) + timedelta(seconds=1)
    )
    state = HostAgentState.for_test(tmp_path, host_ref="worker-one")
    state.accept(item)
    token = state.begin_effect(item)
    assert token is not None
    recovered = state.recover(item)
    assert recovered is not None and recovered.state == "unknown"
    late = state.finish(
        item,
        state="succeeded",
        reason_codes=("done",),
        result=result(item),
        claim_token=token,
    )
    assert late == recovered


def test_recover_wait_is_interruptible(tmp_path: Path) -> None:
    item = lease(
        deadline=datetime.now(UTC).replace(microsecond=0) + timedelta(seconds=10)
    )
    state = HostAgentState.for_test(tmp_path, host_ref="worker-one")
    state.accept(item)
    assert state.begin_effect(item) is not None
    stop = threading.Event()
    stop.set()
    with pytest.raises(HostAgentStateError, match="host.operation_interrupted"):
        state.recover(item, stop_event=stop)


def test_live_process_claim_is_bounded_by_lease_deadline(tmp_path: Path) -> None:
    item = lease(
        deadline=datetime.now(UTC).replace(microsecond=0) + timedelta(seconds=2)
    )
    ready = multiprocessing.Event()
    release = multiprocessing.Event()

    def own() -> None:
        state = HostAgentState.for_test(tmp_path, host_ref="worker-one")
        state.accept(item)
        assert state.begin_effect(item) is not None
        ready.set()
        release.wait(5)

    process = multiprocessing.get_context("fork").Process(target=own)
    process.start()
    try:
        assert ready.wait(2)
        receipt = HostAgentState.for_test(
            tmp_path, host_ref="worker-one"
        ).recover(item)
        assert receipt is not None and receipt.state == "unknown"
        assert process.is_alive()
    finally:
        release.set()
        process.join(3)
        if process.is_alive():
            process.terminate()
            process.join(3)


def test_claim_deadline_ignores_utc_jumps_and_uses_persisted_monotonic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    utc = datetime(2030, 1, 1, tzinfo=UTC)
    monotonic = 100.0
    monkeypatch.setattr(host_agent_state, "_utc_now", lambda: utc)
    monkeypatch.setattr(host_agent_state, "_monotonic", lambda: monotonic)
    item = lease(deadline=utc + timedelta(seconds=20))
    state = HostAgentState.for_test(tmp_path, host_ref="worker-one")
    state.accept(item)
    assert state.begin_effect(item) is not None

    utc += timedelta(days=30)
    stop = threading.Event()
    stop.set()
    with pytest.raises(HostAgentStateError, match="host.operation_interrupted"):
        state.recover(item, stop_event=stop)

    utc -= timedelta(days=60)
    monotonic = 121.0
    receipt = HostAgentState.for_test(
        tmp_path, host_ref="worker-one"
    ).recover(item)
    assert receipt is not None and receipt.state == "unknown"


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
    for changed in (
        {"lease_id": "lease-two"},
        {"attempt": 2},
        {"registry_generation": 8},
        {"lease_epoch": 5},
    ):
        with pytest.raises(HostAgentStateError, match="host.replay_conflict"):
            state.accept(lease(**{"operation_id": "same", "lease_epoch": 4, **changed}))


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


def test_effect_claim_is_atomic_and_only_one_caller_owns_it(tmp_path: Path) -> None:
    item = lease(
        kind="ollama.instance",
        action="apply",
        arguments={"plan_ref": "plan-one"},
        arguments_digest=digest({"plan_ref": "plan-one"}),
    )
    state = HostAgentState.for_test(tmp_path, host_ref="worker-one")
    state.accept(item)
    barrier = threading.Barrier(3)
    claims: list[str | None] = []

    def claim() -> None:
        barrier.wait()
        claims.append(state.begin_effect(item))

    threads = [threading.Thread(target=claim) for _ in range(2)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(2)
    assert all(not thread.is_alive() for thread in threads)
    assert sum(claim is not None for claim in claims) == 1


def test_state_rejects_duplicate_keys_and_incoherent_records(tmp_path: Path) -> None:
    root = tmp_path / "host-agent"
    root.mkdir(mode=0o700)
    state_file = root / "host-agent.json"
    state_file.write_text(
        '{"schema_version":2,"schema_version":2,"highest_lease_epoch":0,'
        '"highest_registry_generation":0,"accepted":{},"receipts":{}}'
    )
    state_file.chmod(0o600)
    with pytest.raises(HostAgentStateError, match="host.state_unavailable"):
        HostAgentState.for_test(tmp_path, host_ref="worker-one")

    state_file.write_text('{"schema_version":NaN}')
    with pytest.raises(HostAgentStateError, match="host.state_unavailable"):
        HostAgentState.for_test(tmp_path, host_ref="worker-one")

    state_file.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "highest_lease_epoch": 0,
                "highest_registry_generation": 0,
                "accepted": {"wrong-map-key": {}},
                "receipts": {},
            }
        )
    )
    with pytest.raises(HostAgentStateError, match="host.state_unavailable"):
        HostAgentState.for_test(tmp_path, host_ref="worker-one")


def test_accepted_records_are_bounded_and_expired_unclaimed_work_is_reclaimed(
    tmp_path: Path,
) -> None:
    state = HostAgentState.for_test(
        tmp_path, host_ref="worker-one", max_accepted=2
    )
    state.accept(lease(operation_id="one", lease_id="lease-one"))
    state.accept(lease(operation_id="two", lease_id="lease-two"))
    with pytest.raises(HostAgentStateError, match="host.accepted_limit"):
        state.accept(lease(operation_id="three", lease_id="lease-three"))

    expired = lease(
        operation_id="expired",
        lease_id="lease-expired",
        deadline=datetime(2020, 1, 1, tzinfo=UTC),
    )
    other = HostAgentState.for_test(
        tmp_path / "expiry", host_ref="worker-one", max_accepted=1
    )
    other.accept(expired)
    other.accept(lease(operation_id="replacement", lease_id="lease-replacement"))
