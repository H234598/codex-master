from datetime import datetime, timezone
from dataclasses import replace
import contextlib
import fcntl
from pathlib import Path
import threading

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
from codex_master import server
from codex_master.hive.hourly_probe import PROBE_GATE_LOCK_NAME, run_probe
from codex_master.server import AgentError, build_server_admission_runtime, build_server_lease_executor, build_server_selection_service
from codex_master.selection_service import SelectionDeniedError, SelectionService


NOW = datetime.now(timezone.utc)


def materialize_green_probe_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    state_directory = tmp_path / "probe-state"
    command = tmp_path / "probe-repository" / "bin" / "codex-master-mcp"
    command.parent.mkdir(parents=True)
    runtime = {
        "schema_version": 1,
        "mode": "enforced",
        "counts": {"principals": 0, "repositories": 0},
        "checks": {"authority": "ready", "repository": "ready", "state": "ready"},
        "config_digest": "sha256:" + "a" * 64,
        "catalog_digest": "sha256:" + "b" * 64,
        "repository": "ready",
        "principal": "ready",
        "authority": "ready",
        "state": "ready",
        "pilot": "ready",
        "reason_codes": [],
        "mutation_performed": False,
        "raw_output": "not_returned",
    }
    checks = {
        "namespace-status": ({"ok": True, "namespace_ready": True}, True),
        "plugin-status": ({"ok": True}, True),
        "hive status": (runtime, True),
        "hive doctor": (
            {"healthy": True, "checks": {"authority": "ready", "repository": "ready", "state": "ready"}},
            True,
        ),
    }
    run_probe(
        repository=tmp_path / "probe-repository",
        command=command,
        state_directory=state_directory,
        now=lambda: NOW,
        runner=lambda _command, *arguments: checks[" ".join(arguments)],
    )
    monkeypatch.setenv("CODEX_MASTER_MCP_STATE", str(state_directory))
    monkeypatch.delenv("CODEX_AGENT_MCP_STATE", raising=False)
    return state_directory


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
    runtime = build_server_admission_runtime(execute=lambda *_args: called.append(True))
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


def test_server_lease_executor_rechecks_binding_and_routes_only_named_operations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[tuple[str, dict[str, object]]] = []
    lease = {"state": "unclaimed", "held_by_this_server": False, "lease_id": None}
    executor = build_server_lease_executor(
        operations={
            "hive_assignment_callback": lambda record, current: seen.append((record.admission_id, dict(current))) or {"status": "ok"},
        },
        lease_reader=lambda _agent: lease,
    )
    monkeypatch.setattr(server, "agent_lifecycle_lock", lambda *_args: contextlib.nullcontext())
    monkeypatch.setattr(server, "hive_capacity_probe_guard", lambda _operation: contextlib.nullcontext())

    result = executor(executing_record(), "hive_assignment_callback")

    assert result == {"status": "ok"}
    assert seen == [("adm-runtime", lease)]
    with pytest.raises(AgentError, match="lease_operation_not_allowed"):
        executor(executing_record(), "hive_assignment_process_start")


def test_server_lease_executor_composes_with_runtime_revalidation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executor = build_server_lease_executor(
        operations={"hive_assignment_callback": lambda _record, lease: {"lease_state": lease["state"]}},
        lease_reader=lambda _agent: {"state": "unclaimed", "held_by_this_server": False, "lease_id": None},
    )
    monkeypatch.setattr(server, "agent_lifecycle_lock", lambda *_args: contextlib.nullcontext())
    monkeypatch.setattr(server, "hive_capacity_probe_guard", lambda _operation: contextlib.nullcontext())
    runtime = ServerAdmissionRuntime(allow_all([]), execute=executor, now=lambda: NOW)
    assert runtime.revalidate(revalidating_record()) is True

    assert runtime.execute(executing_record(), "hive_assignment_callback") == {"lease_state": "unclaimed"}


def test_server_lease_executor_rechecks_after_its_mutation_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[str] = []
    probe_is_green = {"value": True}

    @contextlib.contextmanager
    def mutation_lock(_agent: str):
        seen.append("mutation-lock")
        probe_is_green["value"] = False
        yield

    monkeypatch.setattr(server, "agent_lifecycle_lock", mutation_lock)
    monkeypatch.setattr(server, "probe_capacity_lock", contextlib.nullcontext)
    monkeypatch.setattr(
        server,
        "read_probe_gate",
        lambda: {
            "allowed": probe_is_green["value"],
            "reason_code": "probe_ready" if probe_is_green["value"] else "probe_red",
            "raw_output": "not_returned",
        },
    )
    executor = build_server_lease_executor(
        operations={
            "hive_assignment_callback": lambda *_args: seen.append("callback") or {"status": "unexpected"}
        },
        lease_reader=lambda _agent: {"state": "unclaimed", "held_by_this_server": False, "lease_id": None},
    )

    with pytest.raises(AgentError, match="hive_spawn_probe_blocked"):
        executor(executing_record(), "hive_assignment_callback")

    assert seen == ["mutation-lock"]


@pytest.mark.parametrize(
    ("reason_code", "allowed"),
    (
        ("probe_ready", True),
        ("probe_missing", False),
        ("probe_invalid", False),
        ("probe_stale", False),
        ("probe_red", False),
        ("shadow", False),
        ("disabled", False),
    ),
)
def test_named_hive_assignment_capacity_sink_accepts_only_fresh_green_at_callback(
    monkeypatch: pytest.MonkeyPatch, reason_code: str, allowed: bool
) -> None:
    callback_calls: list[str] = []
    monkeypatch.setattr(server, "agent_lifecycle_lock", lambda *_args: contextlib.nullcontext())
    monkeypatch.setattr(server, "probe_capacity_lock", contextlib.nullcontext)
    monkeypatch.setattr(
        server,
        "read_probe_gate",
        lambda: {
            "allowed": allowed,
            "reason_code": reason_code,
            "raw_output": "not_returned",
        },
    )
    executor = build_server_lease_executor(
        operations={
            "hive_assignment_process_start": lambda *_args: callback_calls.append("process-start")
            or {"status": "started"}
        },
        lease_reader=lambda _agent: {"state": "unclaimed", "held_by_this_server": False, "lease_id": None},
    )

    if allowed:
        assert executor(executing_record(), "hive_assignment_process_start") == {"status": "started"}
    else:
        with pytest.raises(AgentError, match="hive_spawn_probe_blocked"):
            executor(executing_record(), "hive_assignment_process_start")

    assert callback_calls == (["process-start"] if allowed else [])


@pytest.mark.parametrize("operation", sorted(server.HIVE_ASSIGNMENT_CAPACITY_SINKS))
def test_each_hive_assignment_capacity_sink_waits_for_the_real_shared_probe_lock(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, operation: str
) -> None:
    state_directory = materialize_green_probe_record(tmp_path, monkeypatch)
    callback_called = threading.Event()
    completed = threading.Event()
    monkeypatch.setattr(server, "agent_lifecycle_lock", lambda *_args: contextlib.nullcontext())
    executor = build_server_lease_executor(
        operations={operation: lambda *_args: callback_called.set() or {"status": "started"}},
        lease_reader=lambda _agent: {"state": "unclaimed", "held_by_this_server": False, "lease_id": None},
    )

    def execute_sink() -> None:
        assert executor(executing_record(), operation) == {"status": "started"}
        completed.set()

    with (state_directory / PROBE_GATE_LOCK_NAME).open("rb") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        worker = threading.Thread(target=execute_sink)
        worker.start()
        worker.join(timeout=0.1)
        assert worker.is_alive()
        assert not callback_called.is_set()
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    worker.join(timeout=1)
    assert completed.is_set()
    assert callback_called.is_set()


@pytest.mark.parametrize("operation", sorted(server.QUEEN_ASSIGNMENT_CAPACITY_SINKS))
def test_each_queen_capacity_sink_waits_for_the_real_shared_probe_lock(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, operation: str
) -> None:
    state_directory = materialize_green_probe_record(tmp_path, monkeypatch)
    callback_called = threading.Event()
    completed = threading.Event()
    step = operation.removeprefix("queen_assignment_")
    monkeypatch.setattr(server, "agent_lifecycle_lock", lambda *_args: contextlib.nullcontext())

    def execute_sink() -> None:
        plan = type("Plan", (), {"agent_id": "a1"})()
        assert server._execute_server_queen_assignment_capacity_sink(
            step, lambda _plan: callback_called.set() or {"status": "started"}, plan
        ) == {"status": "started"}
        completed.set()

    with (state_directory / PROBE_GATE_LOCK_NAME).open("rb") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        worker = threading.Thread(target=execute_sink)
        worker.start()
        worker.join(timeout=0.1)
        assert worker.is_alive()
        assert not callback_called.is_set()
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    worker.join(timeout=1)
    assert completed.is_set()
    assert callback_called.is_set()


def test_server_lease_executor_rejects_changed_or_non_executing_binding() -> None:
    lease = {"state": "unclaimed", "held_by_this_server": False, "lease_id": None}
    called: list[bool] = []
    executor = build_server_lease_executor(
        operations={"hive_assignment_callback": lambda *_args: called.append(True) or {"status": "ok"}},
        lease_reader=lambda _agent: lease,
    )
    lease["state"] = "held"

    with pytest.raises(AgentError, match="lease_executor_conflict"):
        executor(executing_record(), "hive_assignment_callback")
    with pytest.raises(AgentError, match="invalid_admission_state"):
        executor(revalidating_record(), "hive_assignment_callback")
    assert called == []


def test_server_lease_executor_pins_a_claimed_lease_id() -> None:
    record = executing_record()
    record = replace(record, lease_context=LeaseBinding("claimed", "lease-expected"))
    lease = {"state": "held", "held_by_this_server": True, "lease_id": "lease-other"}
    executor = build_server_lease_executor(
        operations={"hive_assignment_callback": lambda *_args: {"status": "must-not-run"}},
        lease_reader=lambda _agent: lease,
    )

    with pytest.raises(AgentError, match="lease_executor_conflict"):
        executor(record, "hive_assignment_callback")


def test_runtime_gate_exception_and_unknown_completion_fail_closed() -> None:
    gates = allow_all([])
    gates["scope"] = lambda _record: (_ for _ in ()).throw(RuntimeError("scope unavailable"))
    runtime = ServerAdmissionRuntime(gates, execution_completed=lambda _record: "yes")
    record = revalidating_record()

    assert runtime.revalidate(record) is False
    assert runtime.last_failure() == {"allowed": False, "reason_code": "scope_gate_unavailable"}
    assert runtime.execution_completed(record) is False


def test_runtime_rejects_unknown_gate_names() -> None:
    with pytest.raises(AdmissionRuntimeError, match="unknown_runtime_gate"):
        ServerAdmissionRuntime({"typo": None})
