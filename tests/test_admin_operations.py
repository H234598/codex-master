from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
import json
import multiprocessing
from pathlib import Path
import stat
from typing import Any

import pytest

from codex_master.admin_contracts import OperationV1
from codex_master.admin_operations import (
    MAX_HOST_PROBE_LIFECYCLE_OWNERS,
    MAX_HOST_PROBE_LIFECYCLE_STATE_BYTES,
    MAX_OPERATION_RECORDS,
    AdminOperationError,
    AdminOperationStore,
)


NOW = datetime(2026, 8, 28, 10, 0, tzinfo=UTC)
LEGACY_DIGEST = "sha256:b5029f1bcea0a6630628a94cccbed49e025e36551d85fddd6224c7788ca096b5"
V1_STATE_BYTES = 2 * 1024 * 1024
MAX_OWNER_METADATA_BYTES = len(
    b',"owner":{"boot_id":"ffffffff-ffff-ffff-ffff-ffffffffffff",'
    b'"pid":2147483647,"start_ticks":9223372036854775807}'
)
V2_STATE_BYTES = V1_STATE_BYTES + MAX_OPERATION_RECORDS * MAX_OWNER_METADATA_BYTES


class Clock:
    def __init__(self) -> None:
        self.now = NOW

    def __call__(self) -> datetime:
        return self.now


class OwnerProbe:
    def __init__(self, alive: bool | None) -> None:
        self.alive = alive

    def current(self) -> tuple[str, int, int]:
        return ("11111111-1111-1111-1111-111111111111", 1234, 99)

    def is_alive(self, _owner: tuple[str, int, int]) -> bool | None:
        return self.alive


def store_at(
    tmp_path,
    clock: Clock | None = None,
    *,
    owner_probe: OwnerProbe | None = None,
) -> AdminOperationStore:
    kwargs = {"owner_probe": owner_probe} if owner_probe is not None else {}
    return AdminOperationStore.for_test(tmp_path, clock=clock or Clock(), **kwargs)


def test_operation_result_host_probe_binding_resolves_agent_id(tmp_path) -> None:
    """RED: AdminOperationStore cannot yet expose its paired agent operation."""

    store = store_at(tmp_path)
    plan = store.plan(
        kind="hosts.probe",
        generation=4,
        key="public-result-binding",
        steps=("host.probe.collect",),
    )
    store.bind_host_probe_agent(
        plan.operation_id,
        agent_operation_id="agent-operation-one",
        target_host_ref="worker-one",
        plan_digest=plan.plan_digest,
    )

    assert store.agent_operation_id(plan.operation_id) == "agent-operation-one"


def _run_owned_operation(root: str, connection: Any) -> None:
    store = AdminOperationStore.for_test(Path(root), clock=Clock())
    plan = store.plan(
        kind="google.provision",
        generation=4,
        key="restart",
        steps=("create", "probe"),
    )
    store.begin(plan.operation_id, current_generation=4)
    store.record_step(plan.operation_id, "create", succeeded=True)
    connection.send(plan.operation_id)
    connection.recv()


def legacy_v1_record(state: str) -> dict[str, object]:
    step_state = "succeeded" if state == "succeeded" else "not_attempted"
    reason_codes = {
        "planned": ["control.plan_ready"],
        "running": ["control.operation_running"],
        "succeeded": ["control.apply_succeeded"],
    }
    return {
        "id": f"op-v1-{state}",
        "kind": "google.provision",
        "state": state,
        "expected_generation": 4,
        "resulting_generation": 5 if state == "succeeded" else None,
        "plan_digest": LEGACY_DIGEST,
        "created_at": "2026-08-28T10:00:00Z",
        "expires_at": "2026-08-28T10:15:00Z",
        "idempotency_key": f"legacy-{state}",
        "steps": [{"name": "one", "state": step_state, "reason_code": None}],
        "reason_codes": reason_codes[state],
    }


def write_operation_bytes(tmp_path, raw: bytes) -> Path:
    root = tmp_path / "admin-operations"
    root.mkdir(mode=0o700)
    document = root / "operations.json"
    document.write_bytes(raw)
    document.chmod(0o600)
    return document


def write_operation_document(tmp_path, payload: dict[str, object]) -> Path:
    return write_operation_bytes(tmp_path, json.dumps(payload).encode("utf-8"))


def canonical_document(schema_version: int, records: list[dict[str, object]]) -> bytes:
    return (
        json.dumps(
            {"schema_version": schema_version, "operations": records},
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def fixture_digest(steps: list[str]) -> str:
    payload = json.dumps(
        {"generation": 4, "kind": "google.provision", "steps": steps},
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def maximum_v1_records() -> list[dict[str, object]]:
    step_sets = {
        count: [f"s{index}" for index in range(count)] for count in (134, 135)
    }
    digests = {count: fixture_digest(steps) for count, steps in step_sets.items()}
    records = []
    for index in range(MAX_OPERATION_RECORDS):
        count = 135 if index < 192 else 134
        steps = step_sets[count]
        records.append(
            {
                "id": f"op-cap-{index}",
                "kind": "google.provision",
                "state": "planned",
                "expected_generation": 4,
                "resulting_generation": None,
                "plan_digest": digests[count],
                "created_at": "2026-08-28T10:00:00Z",
                "expires_at": "2026-08-28T10:15:00Z",
                "idempotency_key": f"cap-{index}",
                "steps": [
                    {"name": name, "state": "not_attempted", "reason_code": None}
                    for name in steps
                ],
                "reason_codes": ["control.plan_ready"],
            }
        )
    remaining = V1_STATE_BYTES - len(canonical_document(1, records))
    first_key = records[0]["idempotency_key"]
    assert isinstance(first_key, str)
    assert 0 <= remaining <= 128 - len(first_key)
    records[0]["idempotency_key"] = first_key + "x" * remaining
    assert len(canonical_document(1, records)) == V1_STATE_BYTES
    return records


def test_maximum_v1_document_migrates_without_evicting_unexpired_ids(
    tmp_path,
) -> None:
    records = maximum_v1_records()
    document = write_operation_bytes(tmp_path, canonical_document(1, records))
    retained_ids = {record["id"] for record in records}

    store = store_at(tmp_path)
    persisted_raw = document.read_bytes()
    persisted = json.loads(persisted_raw)

    assert len(persisted_raw) == (
        V1_STATE_BYTES + MAX_OPERATION_RECORDS * len(b',"owner":null')
    )
    assert len(persisted_raw) <= V2_STATE_BYTES
    assert persisted["schema_version"] == 2
    assert {record["id"] for record in persisted["operations"]} == retained_ids
    assert store.plan(
        kind="google.provision",
        generation=4,
        key=records[0]["idempotency_key"],
        steps=tuple(step["name"] for step in records[0]["steps"]),
    ).operation_id == records[0]["id"]
    assert store_at(tmp_path).get(records[-1]["id"]).id == records[-1]["id"]


def test_v1_migration_prunes_only_expired_stable_records(tmp_path) -> None:
    expired = legacy_v1_record("planned")
    expired["id"] = "op-v1-expired"
    expired["idempotency_key"] = "legacy-expired"
    expired["created_at"] = "2026-08-28T09:00:00Z"
    expired["expires_at"] = "2026-08-28T09:15:00Z"
    retained = legacy_v1_record("planned")
    document = write_operation_document(
        tmp_path, {"schema_version": 1, "operations": [expired, retained]}
    )

    store = store_at(tmp_path)

    assert [
        record["id"]
        for record in json.loads(document.read_text(encoding="utf-8"))["operations"]
    ] == [retained["id"]]
    assert store.get(retained["id"]).id == retained["id"]
    with pytest.raises(AdminOperationError, match="control.operation_not_found"):
        store.get(expired["id"])


def test_v2_document_one_byte_over_calculated_limit_is_rejected(tmp_path) -> None:
    store = store_at(tmp_path)
    store.plan(kind="google.provision", generation=4, key="oversized", steps=("one",))
    document = tmp_path / "admin-operations" / "operations.json"
    raw = document.read_bytes()
    document.write_bytes(raw + b" " * (V2_STATE_BYTES + 1 - len(raw)))
    document.chmod(0o600)

    with pytest.raises(AdminOperationError, match="control.operation_store_unavailable"):
        store_at(tmp_path)


def test_v1_document_one_byte_over_legacy_limit_is_rejected(tmp_path) -> None:
    raw = canonical_document(1, maximum_v1_records()) + b" "
    assert len(raw) == V1_STATE_BYTES + 1
    assert len(raw) <= V2_STATE_BYTES
    write_operation_bytes(tmp_path, raw)

    with pytest.raises(AdminOperationError, match="control.operation_store_unavailable"):
        store_at(tmp_path)


def test_v2_payload_cannot_consume_one_byte_of_owner_reserve(tmp_path) -> None:
    records = maximum_v1_records()
    key = records[-1]["idempotency_key"]
    assert isinstance(key, str)
    records[-1]["idempotency_key"] = key + "x"
    v2_records = [dict(record, owner=None) for record in records]
    raw = canonical_document(2, v2_records)
    assert len(canonical_document(1, records)) == V1_STATE_BYTES + 1
    assert len(raw) <= V2_STATE_BYTES
    write_operation_bytes(tmp_path, raw)

    with pytest.raises(AdminOperationError, match="control.operation_store_unavailable"):
        store_at(tmp_path)


def test_regular_write_cannot_consume_v2_owner_metadata_reserve(tmp_path) -> None:
    records = maximum_v1_records()[:-1]
    target = V1_STATE_BYTES - 1
    remaining = target - len(canonical_document(1, records))
    for record in records:
        key = record["idempotency_key"]
        assert isinstance(key, str)
        added = min(remaining, 128 - len(key))
        record["idempotency_key"] = key + "x" * added
        remaining -= added
        if remaining == 0:
            break
    assert remaining == 0
    v2_records = [dict(record, owner=None) for record in records]
    raw = canonical_document(2, v2_records)
    assert V1_STATE_BYTES < len(raw) <= V2_STATE_BYTES
    document = write_operation_bytes(tmp_path, raw)
    store = store_at(tmp_path)

    with pytest.raises(AdminOperationError, match="control.operation_limit"):
        store.plan(
            kind="google.provision", generation=4, key="reserve", steps=("one",)
        )

    assert document.read_bytes() == raw


@pytest.mark.parametrize("state", ["planned", "succeeded"])
def test_v1_stable_record_migrates_without_changing_public_identity(
    tmp_path, state: str
) -> None:
    record = legacy_v1_record(state)
    document = write_operation_document(
        tmp_path, {"schema_version": 1, "operations": [record]}
    )

    store = store_at(tmp_path)
    migrated = store.get(record["id"])
    repeated = store.plan(
        kind="google.provision",
        generation=4,
        key=f"legacy-{state}",
        steps=("one",),
    )

    assert migrated.id == f"op-v1-{state}"
    assert migrated.state == state
    assert migrated.plan_digest == LEGACY_DIGEST
    assert migrated.expires_at == NOW + timedelta(minutes=15)
    assert repeated.operation_id == migrated.id
    assert json.loads(document.read_text(encoding="utf-8"))["schema_version"] == 2
    assert store_at(tmp_path).get(migrated.id) == migrated


def test_v1_running_migrates_to_restart_stable_unknown_owner(tmp_path) -> None:
    record = legacy_v1_record("running")
    document = write_operation_document(
        tmp_path, {"schema_version": 1, "operations": [record]}
    )
    dead_probe = OwnerProbe(False)

    migrated = store_at(tmp_path, owner_probe=dead_probe).get(record["id"])
    persisted = json.loads(document.read_text(encoding="utf-8"))

    assert migrated.state == "running"
    assert migrated.id == "op-v1-running"
    assert migrated.plan_digest == LEGACY_DIGEST
    assert migrated.expires_at == NOW + timedelta(minutes=15)
    assert persisted["schema_version"] == 2
    assert persisted["operations"][0]["owner"] == {"status": "unknown"}
    assert store_at(tmp_path, owner_probe=dead_probe).get(migrated.id).state == "running"


def test_unknown_persistence_major_is_rejected(tmp_path) -> None:
    write_operation_document(
        tmp_path,
        {"schema_version": 3, "operations": [legacy_v1_record("planned")]},
    )

    with pytest.raises(AdminOperationError, match="control.operation_store_unavailable"):
        store_at(tmp_path)


def test_owner_aware_v1_running_migrates_without_losing_owner(tmp_path) -> None:
    store = store_at(tmp_path)
    plan = store.plan(
        kind="google.provision", generation=4, key="owner-aware-v1", steps=("one",)
    )
    store.begin(plan.operation_id, current_generation=4)
    document = tmp_path / "admin-operations" / "operations.json"
    payload = json.loads(document.read_text(encoding="utf-8"))
    payload["schema_version"] = 1
    document.write_text(json.dumps(payload), encoding="utf-8")
    document.chmod(0o600)

    migrated = store_at(tmp_path).get(plan.operation_id)

    assert migrated.state == "running"
    assert json.loads(document.read_text(encoding="utf-8"))["schema_version"] == 2


def test_repeated_idempotency_key_returns_same_operation(tmp_path) -> None:
    store = store_at(tmp_path)

    first = store.plan(
        kind="google.provision", generation=7, key="same", steps=("one",)
    )
    second = store.plan(
        kind="google.provision", generation=7, key="same", steps=("one",)
    )

    assert second.operation_id == first.operation_id
    assert second.plan_digest == first.plan_digest
    assert store.get(first.operation_id).state == "planned"


def test_idempotency_key_cannot_be_rebound_to_another_payload(tmp_path) -> None:
    store = store_at(tmp_path)
    first = store.plan(
        kind="google.provision", generation=7, key="same", steps=("one",)
    )

    with pytest.raises(AdminOperationError, match="control.idempotency_conflict"):
        store.plan(
            kind="google.provision", generation=7, key="same", steps=("two",)
        )

    assert store.get(first.operation_id).state == "planned"


def test_unexpired_terminal_capacity_preserves_idempotency_binding(tmp_path) -> None:
    store = store_at(tmp_path)
    first_id = ""
    for index in range(MAX_OPERATION_RECORDS):
        plan = store.plan(
            kind="google.provision",
            generation=7,
            key=f"retained-{index}",
            steps=("one",),
        )
        if index == 0:
            first_id = plan.operation_id
        store.begin(plan.operation_id, current_generation=7)
        store.record_step(plan.operation_id, "one", succeeded=True)
        store.finish(
            plan.operation_id,
            state="succeeded",
            resulting_generation=8,
        )

    repeated = store.plan(
        kind="google.provision", generation=7, key="retained-0", steps=("one",)
    )
    assert repeated.operation_id == first_id
    with pytest.raises(AdminOperationError, match="control.operation_limit"):
        store.plan(
            kind="google.provision", generation=7, key="new", steps=("one",)
        )


def test_expired_planned_records_are_removed_at_record_pressure(tmp_path) -> None:
    clock = Clock()
    store = store_at(tmp_path, clock)
    for index in range(MAX_OPERATION_RECORDS):
        store.plan(
            kind="google.provision",
            generation=7,
            key=f"expired-{index}",
            steps=("one",),
        )
    clock.now += timedelta(minutes=16)

    replacement = store.plan(
        kind="google.provision", generation=8, key="replacement", steps=("one",)
    )

    assert replacement.operation.expected_generation == 8


def test_expired_records_are_removed_at_byte_pressure(tmp_path) -> None:
    clock = Clock()
    store = store_at(tmp_path, clock)
    large_steps = tuple(
        f"step-{index:04d}-" + "x" * 116 for index in range(1_000)
    )
    created = 0
    for index in range(MAX_OPERATION_RECORDS):
        try:
            store.plan(
                kind="google.provision",
                generation=7,
                key=f"large-{index}",
                steps=large_steps,
            )
        except AdminOperationError as exc:
            assert exc.code == "control.operation_limit"
            break
        created += 1
    else:
        pytest.fail("byte capacity was not reached before record capacity")
    assert created < MAX_OPERATION_RECORDS
    clock.now += timedelta(minutes=16)

    replacement = store.plan(
        kind="google.provision",
        generation=8,
        key="large-replacement",
        steps=large_steps,
    )

    assert replacement.operation.expected_generation == 8


def test_byte_capacity_failure_still_persists_safe_expiry_cleanup(tmp_path) -> None:
    clock = Clock()
    store = store_at(tmp_path, clock)
    large_steps = tuple(
        f"step-{index:04d}-" + "x" * 116 for index in range(1_000)
    )
    running_ids = []
    for index in range(11):
        plan = store.plan(
            kind="google.provision",
            generation=7,
            key=f"running-large-{index}",
            steps=large_steps,
        )
        store.begin(plan.operation_id, current_generation=7)
        running_ids.append(plan.operation_id)
    expired = store.plan(
        kind="google.provision", generation=7, key="expired-small", steps=("one",)
    )
    clock.now += timedelta(minutes=16)

    with pytest.raises(AdminOperationError, match="control.operation_limit"):
        store.plan(
            kind="google.provision",
            generation=8,
            key="blocked-by-running",
            steps=large_steps,
        )

    with pytest.raises(AdminOperationError, match="control.operation_not_found"):
        store.get(expired.operation_id)
    assert store.get(running_ids[0]).state == "running"


def test_host_probe_owner_blocks_pruning_until_ack_then_leaves_bounded_tombstone(
    tmp_path,
) -> None:
    clock = Clock()
    store = store_at(tmp_path, clock)
    probe = store.plan(
        kind="hosts.probe",
        generation=4,
        key="durable-host-probe-owner",
        steps=("host.probe.collect",),
    )
    store.bind_host_probe_agent(
        probe.operation_id,
        agent_operation_id="operation-agent-one",
        target_host_ref="worker-one",
        plan_digest=probe.plan_digest,
    )
    clock.now += timedelta(minutes=16)
    store.plan(
        kind="google.provision",
        generation=4,
        key="prune-before-agent-ack",
        steps=("one",),
    )

    assert store.get(probe.operation_id).state == "planned"
    claimed = store.claim_host_probe_agent(
        probe.operation_id,
        agent_operation_id="operation-agent-one",
        target_host_ref="worker-one",
        plan_digest=probe.plan_digest,
    )
    assert claimed.operation is not None
    assert claimed.acknowledged is False
    store.expire_host_probe(
        probe.operation_id,
        expected_generation=4,
        plan_digest=probe.plan_digest,
    )
    store.acknowledge_host_probe_agent(
        probe.operation_id,
        agent_operation_id="operation-agent-one",
        target_host_ref="worker-one",
        plan_digest=probe.plan_digest,
    )
    store.plan(
        kind="google.provision",
        generation=4,
        key="prune-after-agent-ack",
        steps=("one",),
    )

    with pytest.raises(AdminOperationError, match="control.operation_not_found"):
        store.get(probe.operation_id)
    restarted = store_at(tmp_path, clock)
    tombstone = restarted.claim_host_probe_agent(
        probe.operation_id,
        agent_operation_id="operation-agent-one",
        target_host_ref="worker-one",
        plan_digest=probe.plan_digest,
    )
    assert tombstone.operation is None
    assert tombstone.acknowledged is True
    owner_path = tmp_path / "admin-operations" / "host-probe-lifecycle.json"
    owner_bytes = owner_path.read_bytes()
    owner_document = json.loads(owner_bytes)
    assert owner_document["schema_version"] == 1
    assert len(owner_document["owners"]) == 1
    assert len(owner_bytes) <= MAX_HOST_PROBE_LIFECYCLE_STATE_BYTES


def test_unpaired_expired_host_probe_plan_prunes_normally(tmp_path) -> None:
    clock = Clock()
    store = store_at(tmp_path, clock)
    probe = store.plan(
        kind="hosts.probe",
        generation=4,
        key="unpaired-expired-host-probe",
        steps=("host.probe.collect",),
    )
    clock.now += timedelta(minutes=16)

    store.plan(
        kind="google.provision",
        generation=4,
        key="prune-unpaired-host-probe",
        steps=("one",),
    )

    with pytest.raises(AdminOperationError, match="control.operation_not_found"):
        store.get(probe.operation_id)
    assert not (
        tmp_path / "admin-operations" / "host-probe-lifecycle.json"
    ).exists()


def test_host_probe_owner_rejects_wrong_binding_and_missing_operation_without_mutation(
    tmp_path,
) -> None:
    store = store_at(tmp_path)
    probe = store.plan(
        kind="hosts.probe",
        generation=4,
        key="strict-host-probe-owner",
        steps=("host.probe.collect",),
    )
    store.bind_host_probe_agent(
        probe.operation_id,
        agent_operation_id="operation-agent-one",
        target_host_ref="worker-one",
        plan_digest=probe.plan_digest,
    )
    owner_path = tmp_path / "admin-operations" / "host-probe-lifecycle.json"
    before = owner_path.read_bytes()

    for changes in (
        {"agent_operation_id": "operation-agent-two"},
        {"target_host_ref": "worker-two"},
        {"plan_digest": "sha256:" + "0" * 64},
    ):
        arguments = {
            "agent_operation_id": "operation-agent-one",
            "target_host_ref": "worker-one",
            "plan_digest": probe.plan_digest,
            **changes,
        }
        with pytest.raises(
            AdminOperationError, match="control.operation_state_conflict"
        ):
            store.claim_host_probe_agent(probe.operation_id, **arguments)
        assert owner_path.read_bytes() == before

    with pytest.raises(AdminOperationError, match="control.operation_not_found"):
        store.claim_host_probe_agent(
            "op-missing",
            agent_operation_id="operation-missing",
            target_host_ref="worker-one",
            plan_digest=probe.plan_digest,
        )
    assert owner_path.read_bytes() == before


def test_host_probe_owner_rejects_reused_agent_operation_id_without_mutation(
    tmp_path,
) -> None:
    store = store_at(tmp_path)
    first = store.plan(
        kind="hosts.probe",
        generation=4,
        key="first-agent-owner",
        steps=("host.probe.collect",),
    )
    second = store.plan(
        kind="hosts.probe",
        generation=4,
        key="second-agent-owner",
        steps=("host.probe.collect",),
    )
    store.bind_host_probe_agent(
        first.operation_id,
        agent_operation_id="operation-agent-one",
        target_host_ref="worker-one",
        plan_digest=first.plan_digest,
    )
    owner_path = tmp_path / "admin-operations" / "host-probe-lifecycle.json"
    before = owner_path.read_bytes()

    with pytest.raises(
        AdminOperationError, match="control.operation_state_conflict"
    ):
        store.bind_host_probe_agent(
            second.operation_id,
            agent_operation_id="operation-agent-one",
            target_host_ref="worker-one",
            plan_digest=second.plan_digest,
        )

    assert owner_path.read_bytes() == before
    assert store_at(tmp_path).get(first.operation_id).state == "planned"
    assert store_at(tmp_path).get(second.operation_id).state == "planned"


def test_host_probe_owner_capacity_is_bounded(tmp_path, monkeypatch) -> None:
    import codex_master.admin_operations as operations

    monkeypatch.setattr(operations, "MAX_HOST_PROBE_LIFECYCLE_OWNERS", 2)
    store = store_at(tmp_path)
    plans = [
        store.plan(
            kind="hosts.probe",
            generation=4,
            key=f"bounded-owner-{index}",
            steps=("host.probe.collect",),
        )
        for index in range(3)
    ]
    for index, probe in enumerate(plans[:2]):
        store.bind_host_probe_agent(
            probe.operation_id,
            agent_operation_id=f"operation-agent-{index}",
            target_host_ref="worker-one",
            plan_digest=probe.plan_digest,
        )

    with pytest.raises(AdminOperationError, match="control.operation_limit"):
        store.bind_host_probe_agent(
            plans[2].operation_id,
            agent_operation_id="operation-agent-over-limit",
            target_host_ref="worker-one",
            plan_digest=plans[2].plan_digest,
        )

    document = json.loads(
        (tmp_path / "admin-operations" / "host-probe-lifecycle.json").read_text(
            encoding="utf-8"
        )
    )
    assert document["schema_version"] == 1
    assert len(document["owners"]) == 2
    assert MAX_HOST_PROBE_LIFECYCLE_OWNERS == 1_024


def test_host_probe_owner_schema_rejects_unknown_fields(tmp_path) -> None:
    store = store_at(tmp_path)
    probe = store.plan(
        kind="hosts.probe",
        generation=4,
        key="owner-schema",
        steps=("host.probe.collect",),
    )
    store.bind_host_probe_agent(
        probe.operation_id,
        agent_operation_id="operation-agent-one",
        target_host_ref="worker-one",
        plan_digest=probe.plan_digest,
    )
    owner_path = tmp_path / "admin-operations" / "host-probe-lifecycle.json"
    document = json.loads(owner_path.read_text(encoding="utf-8"))
    document["owners"][0]["unexpected"] = True
    owner_path.write_text(json.dumps(document), encoding="utf-8")
    owner_path.chmod(0o600)

    with pytest.raises(AdminOperationError, match="control.operation_store_unavailable"):
        store_at(tmp_path)


@pytest.mark.parametrize(
    ("kind", "generation", "steps"),
    [
        ("google.remove", 7, ("one", "two")),
        ("google.provision", 8, ("one", "two")),
        ("google.provision", 7, ("two", "one")),
    ],
)
def test_plan_digest_binds_kind_generation_and_ordered_steps(
    tmp_path, kind: str, generation: int, steps: tuple[str, ...]
) -> None:
    store = store_at(tmp_path)
    baseline = store.plan(
        kind="google.provision",
        generation=7,
        key="baseline",
        steps=("one", "two"),
    )

    changed = store.plan(
        kind=kind, generation=generation, key=f"changed-{kind}-{generation}", steps=steps
    )

    assert changed.plan_digest != baseline.plan_digest
    assert baseline.plan_digest.startswith("sha256:")
    assert len(baseline.plan_digest) == 71


def test_stale_generation_changes_nothing(tmp_path) -> None:
    store = store_at(tmp_path)
    plan = store.plan(
        kind="google.provision", generation=4, key="x", steps=("one",)
    )

    with pytest.raises(AdminOperationError, match="control.plan_stale"):
        store.begin(plan.operation_id, current_generation=5)

    operation = store.get(plan.operation_id)
    assert operation.state == "planned"
    assert operation.completed_count == 0
    assert operation.failed_count == 0
    assert operation.not_attempted_count == 1


def test_step_progress_and_finish_survive_restart(tmp_path) -> None:
    clock = Clock()
    store = store_at(tmp_path, clock)
    plan = store.plan(
        kind="google.provision",
        generation=4,
        key="progress",
        steps=("create", "probe"),
    )
    running = store.begin(plan.operation_id, current_generation=4)
    progressed = store.record_step(
        plan.operation_id, "create", succeeded=True
    )
    store.record_step(plan.operation_id, "probe", succeeded=True)
    clock.now += timedelta(seconds=5)
    finished = store.finish(
        plan.operation_id,
        state="succeeded",
        resulting_generation=5,
        reason_codes=("control.apply_succeeded",),
    )

    assert isinstance(running, OperationV1)
    assert running.state == "running"
    assert progressed.completed_count == 1
    assert progressed.not_attempted_count == 1
    assert finished.state == "succeeded"
    assert finished.resulting_generation == 5
    assert finished.completed_count == 2
    assert finished.failed_count == 0
    assert finished.not_attempted_count == 0
    assert finished.created_at == NOW
    assert finished.expires_at == NOW + timedelta(minutes=15)
    assert finished.reason_codes == ("control.apply_succeeded",)
    assert store_at(tmp_path, clock).get(plan.operation_id) == finished


def test_running_operation_reconciles_only_after_owner_process_exits(tmp_path) -> None:
    context = multiprocessing.get_context("fork")
    parent, child = context.Pipe()
    process = context.Process(target=_run_owned_operation, args=(str(tmp_path), child))
    process.start()
    try:
        operation_id = parent.recv()

        assert store_at(tmp_path).get(operation_id).state == "running"

        parent.send("exit")
        process.join(timeout=10)
        assert process.exitcode == 0
        recovered = store_at(tmp_path).get(operation_id)
        assert recovered.state == "partial"
        assert recovered.completed_count == 1
        assert recovered.failed_count == 0
        assert recovered.not_attempted_count == 1
        assert recovered.reason_codes == ("control.restart_reconciled",)
    finally:
        if process.is_alive():
            process.terminate()
            process.join(timeout=10)


def test_only_restart_reconciled_host_probe_can_be_resumed(tmp_path) -> None:
    dead_probe = OwnerProbe(False)
    store = store_at(tmp_path, owner_probe=dead_probe)
    probe = store.plan(
        kind="hosts.probe",
        generation=4,
        key="resume-host-probe",
        steps=("host.probe.collect",),
    )
    store.begin(probe.operation_id, current_generation=4)
    recovered = store_at(tmp_path, owner_probe=dead_probe)

    resumed = recovered.resume_host_probe(
        probe.operation_id, expected_generation=4
    )

    assert resumed.state == "running"
    assert resumed.not_attempted_count == 1

    other = recovered.plan(
        kind="google.provision",
        generation=4,
        key="do-not-resume-other-owner",
        steps=("host.probe.collect",),
    )
    recovered.begin(other.operation_id, current_generation=4)
    restarted = store_at(tmp_path, owner_probe=dead_probe)
    with pytest.raises(AdminOperationError, match="control.operation_state_conflict"):
        restarted.resume_host_probe(other.operation_id, expected_generation=4)

    ordinary_partial = restarted.plan(
        kind="hosts.probe",
        generation=4,
        key="do-not-resume-ordinary-partial",
        steps=("host.probe.collect",),
    )
    restarted.begin(ordinary_partial.operation_id, current_generation=4)
    restarted.record_step(
        ordinary_partial.operation_id,
        "host.probe.collect",
        succeeded=False,
        reason_code="host.probe_failed",
    )
    restarted.finish(
        ordinary_partial.operation_id,
        state="partial",
        reason_codes=("host.probe_failed",),
    )
    with pytest.raises(AdminOperationError, match="control.operation_state_conflict"):
        restarted.resume_host_probe(
            ordinary_partial.operation_id, expected_generation=4
        )


def test_expired_restart_reconciled_host_probe_cannot_be_resumed(tmp_path) -> None:
    clock = Clock()
    dead_probe = OwnerProbe(False)
    store = store_at(tmp_path, clock, owner_probe=dead_probe)
    probe = store.plan(
        kind="hosts.probe",
        generation=4,
        key="expired-resume-host-probe",
        steps=("host.probe.collect",),
    )
    store.begin(probe.operation_id, current_generation=4)
    clock.now += timedelta(minutes=16)
    recovered = store_at(tmp_path, clock, owner_probe=dead_probe)

    with pytest.raises(AdminOperationError, match="control.plan_expired"):
        recovered.resume_host_probe(probe.operation_id, expected_generation=4)

    assert recovered.get(probe.operation_id).state == "partial"
    terminal = recovered.expire_host_probe(
        probe.operation_id,
        expected_generation=4,
        plan_digest=probe.plan_digest,
    )
    assert terminal.state == "failed"
    assert terminal.reason_codes == ("host.probe_unknown",)


def test_expired_restart_reconciled_failed_host_probe_terminalizes(
    tmp_path,
) -> None:
    clock = Clock()
    dead_probe = OwnerProbe(False)
    store = store_at(tmp_path, clock, owner_probe=dead_probe)
    probe = store.plan(
        kind="hosts.probe",
        generation=4,
        key="expired-failed-host-probe",
        steps=("host.probe.collect",),
    )
    store.begin(probe.operation_id, current_generation=4)
    store.record_step(
        probe.operation_id,
        "host.probe.collect",
        succeeded=False,
        reason_code="host.probe_unknown",
    )
    clock.now += timedelta(minutes=16)
    recovered = store_at(tmp_path, clock, owner_probe=dead_probe)
    assert recovered.get(probe.operation_id).state == "partial"

    terminal = recovered.expire_host_probe(
        probe.operation_id,
        expected_generation=4,
        plan_digest=probe.plan_digest,
    )

    assert terminal.state == "failed"
    assert terminal.failed_count == 1
    assert terminal.reason_codes == ("host.probe_unknown",)


@pytest.mark.parametrize(
    ("step_state", "step_reason", "expected_state", "expected_reason"),
    (
        ("not_attempted", None, "failed", "host.probe_unknown"),
        ("failed", "host.probe_unknown", "failed", "host.probe_unknown"),
        ("failed", "host.probe_failed", "failed", "host.probe_failed"),
        ("succeeded", None, "partial", "control.restart_reconciled"),
    ),
)
def test_expired_restart_reconciled_host_probe_accepts_every_durable_step_shape(
    tmp_path,
    step_state: str,
    step_reason: str | None,
    expected_state: str,
    expected_reason: str,
) -> None:
    clock = Clock()
    dead_probe = OwnerProbe(False)
    store = store_at(tmp_path, clock, owner_probe=dead_probe)
    probe = store.plan(
        kind="hosts.probe",
        generation=4,
        key=f"expired-shape-{step_state}-{step_reason}",
        steps=("host.probe.collect",),
    )
    store.begin(probe.operation_id, current_generation=4)
    if step_state != "not_attempted":
        store.record_step(
            probe.operation_id,
            "host.probe.collect",
            succeeded=step_state == "succeeded",
            reason_code=step_reason,
        )
    clock.now += timedelta(minutes=16)
    recovered = store_at(tmp_path, clock, owner_probe=dead_probe)
    before = recovered.get(probe.operation_id)
    assert before.state == "partial"
    assert before.reason_codes == ("control.restart_reconciled",)

    terminal = recovered.expire_host_probe(
        probe.operation_id,
        expected_generation=4,
        plan_digest=probe.plan_digest,
    )

    assert terminal.state == expected_state
    assert terminal.reason_codes == (expected_reason,)
    assert terminal.completed_count == (step_state == "succeeded")
    assert terminal.failed_count == (step_state == "failed" or step_state == "not_attempted")
    assert recovered.expire_host_probe(
        probe.operation_id,
        expected_generation=4,
        plan_digest=probe.plan_digest,
    ) == terminal
    assert store_at(tmp_path, clock, owner_probe=dead_probe).get(probe.operation_id) == terminal


def test_expired_restart_reconciled_host_probe_rejects_noncanonical_step_shape(
    tmp_path,
) -> None:
    clock = Clock()
    dead_probe = OwnerProbe(False)
    store = store_at(tmp_path, clock, owner_probe=dead_probe)
    probe = store.plan(
        kind="hosts.probe",
        generation=4,
        key="expired-invalid-succeeded-reason",
        steps=("host.probe.collect",),
    )
    store.begin(probe.operation_id, current_generation=4)
    store.record_step(
        probe.operation_id,
        "host.probe.collect",
        succeeded=True,
        reason_code="host.probe_failed",
    )
    clock.now += timedelta(minutes=16)
    recovered = store_at(tmp_path, clock, owner_probe=dead_probe)
    before = recovered.get(probe.operation_id)

    with pytest.raises(AdminOperationError, match="control.operation_state_conflict"):
        recovered.expire_host_probe(
            probe.operation_id,
            expected_generation=4,
            plan_digest=probe.plan_digest,
        )

    assert recovered.get(probe.operation_id) == before


def test_expired_restart_reconciled_host_probe_rejects_resulting_generation(
    tmp_path,
) -> None:
    clock = Clock()
    dead_probe = OwnerProbe(False)
    store = store_at(tmp_path, clock, owner_probe=dead_probe)
    probe = store.plan(
        kind="hosts.probe",
        generation=4,
        key="expired-invalid-resulting-generation",
        steps=("host.probe.collect",),
    )
    store.begin(probe.operation_id, current_generation=4)
    clock.now += timedelta(minutes=16)
    recovered = store_at(tmp_path, clock, owner_probe=dead_probe)
    document_path = tmp_path / "admin-operations" / "operations.json"
    document = json.loads(document_path.read_text(encoding="utf-8"))
    document["operations"][0]["resulting_generation"] = 5
    document_path.write_text(
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    document_path.chmod(0o600)
    recovered = store_at(tmp_path, clock, owner_probe=dead_probe)
    before = document_path.read_bytes()

    with pytest.raises(AdminOperationError, match="control.operation_state_conflict"):
        recovered.expire_host_probe(
            probe.operation_id,
            expected_generation=4,
            plan_digest=probe.plan_digest,
        )

    assert document_path.read_bytes() == before


def test_expired_planned_host_probe_has_one_exact_idempotent_failure_transition(
    tmp_path,
) -> None:
    clock = Clock()
    store = store_at(tmp_path, clock)
    probe = store.plan(
        kind="hosts.probe",
        generation=4,
        key="expired-planned-host-probe",
        steps=("host.probe.collect",),
    )

    with pytest.raises(AdminOperationError, match="control.operation_state_conflict"):
        store.expire_host_probe(
            probe.operation_id,
            expected_generation=4,
            plan_digest=probe.plan_digest,
        )
    clock.now += timedelta(minutes=16)

    with pytest.raises(AdminOperationError, match="control.operation_state_conflict"):
        store.expire_host_probe(
            probe.operation_id,
            expected_generation=4,
            plan_digest="sha256:" + "0" * 64,
        )
    terminal = store.expire_host_probe(
        probe.operation_id,
        expected_generation=4,
        plan_digest=probe.plan_digest,
    )

    assert terminal.state == "failed"
    assert terminal.failed_count == 1
    assert terminal.not_attempted_count == 0
    assert terminal.reason_codes == ("host.probe_unknown",)
    assert store.expire_host_probe(
        probe.operation_id,
        expected_generation=4,
        plan_digest=probe.plan_digest,
    ) == terminal


@pytest.mark.parametrize(
    ("kind", "generation", "steps"),
    (
        ("google.provision", 4, ("host.probe.collect",)),
        ("hosts.probe", 5, ("host.probe.collect",)),
        ("hosts.probe", 4, ("other",)),
    ),
)
def test_expired_host_probe_transition_rejects_non_exact_pair(
    tmp_path,
    kind: str,
    generation: int,
    steps: tuple[str, ...],
) -> None:
    clock = Clock()
    store = store_at(tmp_path, clock)
    operation = store.plan(
        kind=kind,
        generation=generation,
        key=f"reject-expired-{kind}-{generation}-{steps[0]}",
        steps=steps,
    )
    clock.now += timedelta(minutes=16)

    with pytest.raises(AdminOperationError, match="control.operation_state_conflict"):
        store.expire_host_probe(
            operation.operation_id,
            expected_generation=4,
            plan_digest=operation.plan_digest,
        )

    assert store.get(operation.operation_id).state == "planned"


def test_unknown_owner_status_keeps_running_operation_unchanged(tmp_path) -> None:
    probe = OwnerProbe(None)
    store = store_at(tmp_path, owner_probe=probe)
    plan = store.plan(
        kind="google.provision", generation=4, key="unknown-owner", steps=("one",)
    )
    store.begin(plan.operation_id, current_generation=4)

    restarted = store_at(tmp_path, owner_probe=probe)

    assert restarted.get(plan.operation_id).state == "running"


def test_failed_step_is_counted_once(tmp_path) -> None:
    store = store_at(tmp_path)
    plan = store.plan(
        kind="google.provision", generation=4, key="failed", steps=("probe",)
    )
    store.begin(plan.operation_id, current_generation=4)
    failed = store.record_step(
        plan.operation_id,
        "probe",
        succeeded=False,
        reason_code="control.probe_failed",
    )

    with pytest.raises(AdminOperationError, match="control.step_already_recorded"):
        store.record_step(plan.operation_id, "probe", succeeded=False)

    assert failed.completed_count == 0
    assert failed.failed_count == 1
    assert failed.not_attempted_count == 0
    assert failed.reason_codes == ("control.probe_failed",)


def test_default_failure_reason_survives_later_progress(tmp_path) -> None:
    store = store_at(tmp_path)
    plan = store.plan(
        kind="google.provision",
        generation=4,
        key="failure-reason",
        steps=("create", "probe"),
    )
    store.begin(plan.operation_id, current_generation=4)
    store.record_step(plan.operation_id, "create", succeeded=False)

    progressed = store.record_step(plan.operation_id, "probe", succeeded=True)

    assert progressed.reason_codes == ("control.step_failed",)


def test_failed_finish_does_not_require_resulting_generation(tmp_path) -> None:
    store = store_at(tmp_path)
    plan = store.plan(
        kind="google.provision", generation=4, key="finish-failed", steps=("probe",)
    )
    store.begin(plan.operation_id, current_generation=4)
    store.record_step(plan.operation_id, "probe", succeeded=False)

    finished = store.finish(
        plan.operation_id,
        state="failed",
        reason_codes=("control.apply_failed",),
    )

    assert finished.state == "failed"
    assert finished.resulting_generation is None


def test_failed_finish_preserves_step_failure_reason_when_codes_omitted(
    tmp_path,
) -> None:
    store = store_at(tmp_path)
    plan = store.plan(
        kind="google.provision", generation=4, key="finish-reason", steps=("probe",)
    )
    store.begin(plan.operation_id, current_generation=4)
    store.record_step(
        plan.operation_id,
        "probe",
        succeeded=False,
        reason_code="control.probe_failed",
    )

    finished = store.finish(plan.operation_id, state="failed")

    assert finished.reason_codes == ("control.probe_failed",)


def test_state_files_remain_private(tmp_path) -> None:
    store = store_at(tmp_path)
    store.plan(kind="google.provision", generation=1, key="private", steps=("one",))
    root = tmp_path / "admin-operations"

    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert stat.S_IMODE((root / "operations.json").stat().st_mode) == 0o600
    assert stat.S_IMODE((root / ".hive-state.lock").stat().st_mode) == 0o600


def test_operation_document_symlink_is_rejected(tmp_path) -> None:
    store = store_at(tmp_path)
    plan = store.plan(
        kind="google.provision", generation=1, key="safe", steps=("one",)
    )
    document = tmp_path / "admin-operations" / "operations.json"
    target = tmp_path / "outside.json"
    target.write_text("{}", encoding="utf-8")
    document.unlink()
    document.symlink_to(target)

    with pytest.raises(AdminOperationError, match="control.operation_store_unavailable"):
        store.get(plan.operation_id)

    assert target.read_text(encoding="utf-8") == "{}"


def test_lock_symlink_is_reported_as_generic_store_error(tmp_path) -> None:
    store = store_at(tmp_path)
    plan = store.plan(
        kind="google.provision", generation=1, key="lock-safe", steps=("one",)
    )
    lock = tmp_path / "admin-operations" / ".hive-state.lock"
    target = tmp_path / "outside.lock"
    target.write_text("unchanged", encoding="utf-8")
    lock.unlink()
    lock.symlink_to(target)

    with pytest.raises(AdminOperationError, match="control.operation_store_unavailable"):
        store.get(plan.operation_id)

    assert target.read_text(encoding="utf-8") == "unchanged"


def test_restart_rejects_digest_not_bound_to_persisted_plan(tmp_path) -> None:
    store = store_at(tmp_path)
    store.plan(
        kind="google.provision", generation=1, key="digest-safe", steps=("one",)
    )
    document = tmp_path / "admin-operations" / "operations.json"
    payload = json.loads(document.read_text(encoding="utf-8"))
    payload["operations"][0]["plan_digest"] = "sha256:" + "0" * 64
    document.write_text(json.dumps(payload), encoding="utf-8")
    document.chmod(0o600)

    with pytest.raises(AdminOperationError, match="control.operation_store_unavailable"):
        store_at(tmp_path)


@pytest.mark.parametrize(
    "mutation",
    ["succeeded_with_pending", "planned_with_completed", "running_with_result"],
)
def test_restart_rejects_state_machine_tampering(tmp_path, mutation: str) -> None:
    store = store_at(tmp_path)
    plan = store.plan(
        kind="google.provision", generation=4, key="state-safe", steps=("one",)
    )
    if mutation == "running_with_result":
        store.begin(plan.operation_id, current_generation=4)
    document = tmp_path / "admin-operations" / "operations.json"
    payload = json.loads(document.read_text(encoding="utf-8"))
    record = payload["operations"][0]
    if mutation == "succeeded_with_pending":
        record["state"] = "succeeded"
        record["resulting_generation"] = None
    elif mutation == "planned_with_completed":
        record["steps"][0]["state"] = "succeeded"
    else:
        record["resulting_generation"] = 5
    document.write_text(json.dumps(payload), encoding="utf-8")
    document.chmod(0o600)

    with pytest.raises(AdminOperationError, match="control.operation_store_unavailable"):
        store_at(tmp_path)


def test_finish_rejects_generation_regression(tmp_path) -> None:
    store = store_at(tmp_path)
    plan = store.plan(
        kind="google.provision", generation=4, key="generation", steps=("one",)
    )
    store.begin(plan.operation_id, current_generation=4)
    store.record_step(
        plan.operation_id,
        "one",
        succeeded=False,
        reason_code="control.step_failed",
    )

    with pytest.raises(AdminOperationError, match="control.operation_invalid"):
        store.finish(
            plan.operation_id,
            state="failed",
            resulting_generation=3,
            reason_codes=("control.apply_failed",),
        )
