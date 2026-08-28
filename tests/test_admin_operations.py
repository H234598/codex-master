from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
import stat

import pytest

from codex_master.admin_contracts import OperationV1
from codex_master.admin_operations import AdminOperationError, AdminOperationStore


NOW = datetime(2026, 8, 28, 10, 0, tzinfo=UTC)


class Clock:
    def __init__(self) -> None:
        self.now = NOW

    def __call__(self) -> datetime:
        return self.now


def store_at(tmp_path, clock: Clock | None = None) -> AdminOperationStore:
    return AdminOperationStore.for_test(tmp_path, clock=clock or Clock())


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


def test_restart_reconciles_running_operation_to_partial(tmp_path) -> None:
    clock = Clock()
    store = store_at(tmp_path, clock)
    plan = store.plan(
        kind="google.provision",
        generation=4,
        key="restart",
        steps=("create", "probe"),
    )
    store.begin(plan.operation_id, current_generation=4)
    store.record_step(plan.operation_id, "create", succeeded=True)

    restarted = store_at(tmp_path, clock)
    recovered = restarted.get(plan.operation_id)

    assert recovered.state == "partial"
    assert recovered.completed_count == 1
    assert recovered.failed_count == 0
    assert recovered.not_attempted_count == 1
    assert recovered.reason_codes == ("control.restart_reconciled",)
    assert store_at(tmp_path, clock).get(plan.operation_id) == recovered


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
