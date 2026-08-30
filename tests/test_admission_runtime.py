from datetime import datetime, timezone
from dataclasses import replace

import pytest

from codex_master.admission import (
    AdmissionPriority,
    AdmissionState,
    AdmissionStore,
    FileAdmissionStore,
    LeaseBinding,
    ResourceBinding,
    ScopeBinding,
    create_admission,
)
from codex_master.admission_runtime import (
    ADMISSION_RUNTIME_GATES,
    AdmissionRuntimeError,
    RuntimeGateDecision,
    ServerAdmissionRuntime,
)
from codex_master.server import AgentError, build_server_admission_runtime, build_server_lease_executor, build_server_selection_service
from codex_master.selection_service import SelectionDeniedError, SelectionService


NOW = datetime.now(timezone.utc)


def admission() -> object:
    return create_admission(
        admission_id="adm-runtime",
        request_id="req-runtime",
        dispatch_id="dsp-runtime",
        workpackage_id="wp-runtime",
        assignment_intent_id="intent-runtime",
        repo_id="codex-master",
        principal_id="specialist-1",
        parent_principal_id="teamlead-1",
        grant_id="grant-runtime",
        grant_digest="sha256:grant-runtime",
        work_item_version=1,
        scope=ScopeBinding("write", ("src",), "sha256:scope-runtime"),
        resource=ResourceBinding("a1", "account-a", "standard", "gpt-primary", 1),
        lease_context=LeaseBinding("available"),
        priority=AdmissionPriority("DP1", "selection"),
        now=NOW,
    )


def revalidating_record():
    store = AdmissionStore()
    reserved = store.reserve(admission(), now=NOW)
    return store.begin_revalidation(reserved.admission_id, expected_revision=1, now=NOW)


def executing_record():
    store = AdmissionStore()
    reserved = store.reserve(admission(), now=NOW)
    revalidating = store.begin_revalidation(reserved.admission_id, expected_revision=1, now=NOW)
    admitted = store.complete_revalidation(
        revalidating.admission_id,
        expected_revision=revalidating.revision,
        valid=True,
        now=NOW,
    )
    return store.begin_execution(admitted.admission_id, expected_revision=admitted.revision, now=NOW)


def allow_all(events: list[str]):
    return {
        name: (lambda _record, name=name: events.append(name) or RuntimeGateDecision(True, f"{name}_verified"))
        for name in ADMISSION_RUNTIME_GATES
    }


def test_runtime_requires_every_gate_in_fixed_order_before_execute() -> None:
    events: list[str] = []
    runtime = ServerAdmissionRuntime(
        allow_all(events),
        execute=lambda _record, operation: {"operation": operation, "status": "ok"},
        now=lambda: NOW,
    )
    record = revalidating_record()

    assert runtime.revalidate(record) is True
    assert events == list(ADMISSION_RUNTIME_GATES)
    executing = executing_record()
    assert runtime.execute(executing, "assign") == {"operation": "assign", "status": "ok"}


def test_runtime_composes_with_selection_service_revision_transitions() -> None:
    executed: list[str] = []
    runtime = ServerAdmissionRuntime(
        allow_all([]),
        execute=lambda _record, operation: executed.append(operation) or {"status": "ok"},
        now=lambda: NOW,
    )
    store = AdmissionStore()
    service = SelectionService(store, runtime, now=lambda: NOW, sleeper=lambda _delay: None)

    result = service.execute_with_retry(lambda: admission(), "start")

    assert result["admission"]["state"] == AdmissionState.FINALIZED.value
    assert executed == ["start"]


def test_server_selection_factory_uses_persistent_store_but_missing_hive_stays_closed(tmp_path) -> None:
    state_path = tmp_path / "admissions.json"
    lock_path = tmp_path / "admission.lock"
    service = build_server_selection_service(
        state_path=state_path,
        lock_path=lock_path,
        execute=lambda *_args: pytest.fail("executor must not run"),
        now=lambda: NOW,
        sleeper=lambda _delay: None,
    )

    with pytest.raises(SelectionDeniedError, match="admission revalidation denied"):
        service.execute_with_retry(lambda: admission(), "assign")
    persisted = FileAdmissionStore(state_path, lock_path).get("adm-runtime")
    assert persisted.state is AdmissionState.COMPENSATED


def test_selection_service_persists_every_transition_with_file_store(tmp_path) -> None:
    store = FileAdmissionStore(tmp_path / "admissions.json", tmp_path / "admission.lock")
    runtime = ServerAdmissionRuntime(
        allow_all([]),
        execute=lambda _record, _operation: {"status": "ok"},
        now=lambda: NOW,
    )
    result = SelectionService(store, runtime, now=lambda: NOW, sleeper=lambda _delay: None).execute_with_retry(
        lambda: admission(), "start"
    )

    fresh = FileAdmissionStore(tmp_path / "admissions.json", tmp_path / "admission.lock")
    stored = fresh.get(result["admission"]["admission_id"])
    assert stored.state is AdmissionState.FINALIZED
    assert stored.revision == result["admission"]["revision"]


def test_runtime_missing_hive_bindings_denies_and_never_executes() -> None:
    called = []
    runtime = build_server_admission_runtime(
        execute=lambda *_args: called.append(True), now=lambda: NOW
    )
    record = revalidating_record()

    assert runtime.revalidate(record) is False
    assert runtime.last_failure() == {"allowed": False, "reason_code": "missing_authority_gate"}
    assert called == []
    with pytest.raises(AdmissionRuntimeError, match="invalid_admission_state"):
        runtime.execute(record, "assign")


def test_runtime_revalidation_is_single_use_and_executor_is_required() -> None:
    runtime = ServerAdmissionRuntime(allow_all([]), now=lambda: NOW)
    record = revalidating_record()

    assert runtime.revalidate(record) is True
    executing = executing_record()
    with pytest.raises(AdmissionRuntimeError, match="runtime_execution_unavailable"):
        runtime.execute(executing, "start")
    with pytest.raises(AdmissionRuntimeError, match="runtime_not_revalidated"):
        runtime.execute(executing, "start")


def test_server_lease_executor_rechecks_binding_and_routes_only_named_operations() -> None:
    seen: list[tuple[str, dict[str, object]]] = []
    lease = {"state": "unclaimed", "held_by_this_server": False, "lease_id": None}
    executor = build_server_lease_executor(
        operations={
            "assign": lambda record, current: seen.append((record.admission_id, dict(current))) or {"status": "ok"},
        },
        lease_reader=lambda _agent: lease,
    )

    result = executor(executing_record(), "assign")

    assert result == {"status": "ok"}
    assert seen == [("adm-runtime", lease)]
    with pytest.raises(AgentError, match="lease_operation_not_allowed"):
        executor(executing_record(), "start")


def test_server_lease_executor_composes_with_runtime_revalidation() -> None:
    executor = build_server_lease_executor(
        operations={"assign": lambda _record, lease: {"lease_state": lease["state"]}},
        lease_reader=lambda _agent: {"state": "unclaimed", "held_by_this_server": False, "lease_id": None},
    )
    runtime = ServerAdmissionRuntime(allow_all([]), execute=executor, now=lambda: NOW)
    assert runtime.revalidate(revalidating_record()) is True

    assert runtime.execute(executing_record(), "assign") == {"lease_state": "unclaimed"}


def test_server_lease_executor_rejects_changed_or_non_executing_binding() -> None:
    lease = {"state": "unclaimed", "held_by_this_server": False, "lease_id": None}
    called: list[bool] = []
    executor = build_server_lease_executor(
        operations={"assign": lambda *_args: called.append(True) or {"status": "ok"}},
        lease_reader=lambda _agent: lease,
    )
    lease["state"] = "held"

    with pytest.raises(AgentError, match="lease_executor_conflict"):
        executor(executing_record(), "assign")
    with pytest.raises(AgentError, match="invalid_admission_state"):
        executor(revalidating_record(), "assign")
    assert called == []


def test_server_lease_executor_pins_a_claimed_lease_id() -> None:
    record = executing_record()
    record = replace(record, lease_context=LeaseBinding("claimed", "lease-expected"))
    lease = {"state": "held", "held_by_this_server": True, "lease_id": "lease-other"}
    executor = build_server_lease_executor(
        operations={"assign": lambda *_args: {"status": "must-not-run"}},
        lease_reader=lambda _agent: lease,
    )

    with pytest.raises(AgentError, match="lease_executor_conflict"):
        executor(record, "assign")


def test_runtime_gate_exception_and_unknown_completion_fail_closed() -> None:
    gates = allow_all([])
    gates["scope"] = lambda _record: (_ for _ in ()).throw(RuntimeError("scope unavailable"))
    runtime = ServerAdmissionRuntime(
        gates, execution_completed=lambda _record: "yes", now=lambda: NOW
    )
    record = revalidating_record()

    assert runtime.revalidate(record) is False
    assert runtime.last_failure() == {"allowed": False, "reason_code": "scope_gate_unavailable"}
    assert runtime.execution_completed(record) is False


def test_runtime_rejects_unknown_gate_names() -> None:
    with pytest.raises(AdmissionRuntimeError, match="unknown_runtime_gate"):
        ServerAdmissionRuntime({"typo": None})
