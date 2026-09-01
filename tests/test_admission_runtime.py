from datetime import datetime, timedelta, timezone
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
from codex_master.hive.dispatch import plan_queen_assignment
from codex_master.hive.hourly_probe import PROBE_GATE_LOCK_NAME, run_probe
from codex_master.server import AgentError, build_server_admission_runtime, build_server_lease_executor, build_server_selection_service
from codex_master.selection_service import SelectionDeniedError, SelectionService


NOW = datetime.now(timezone.utc)


def materialize_probe_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, probe_state: str
) -> Path:
    state_directory = tmp_path / "probe-state"
    command = tmp_path / "probe-repository" / "bin" / "codex-master-mcp"
    command.parent.mkdir(parents=True, exist_ok=True)
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
    if probe_state in {"shadow", "disabled"}:
        runtime["mode"] = probe_state
    checks = {
        "namespace-status": ({"ok": True, "namespace_ready": True}, True),
        "plugin-status": ({"ok": True}, True),
        "hive status": (runtime, True),
        "hive doctor": (
            {"healthy": True, "checks": {"authority": "ready", "repository": "ready", "state": "ready"}},
            True,
        ),
    }
    reference = datetime.now(timezone.utc)
    run_probe(
        repository=tmp_path / "probe-repository",
        command=command,
        state_directory=state_directory,
        now=lambda: (
            reference - timedelta(seconds=4 * 60 * 60 + 1)
            if probe_state == "stale"
            else reference
        ),
        runner=(
            (lambda _command, *_arguments: ({}, False))
            if probe_state == "red"
            else lambda _command, *arguments: checks[" ".join(arguments)]
        ),
    )
    state_file = state_directory / "hive-hourly-health.json"
    if probe_state == "missing":
        state_file.unlink()
    elif probe_state == "invalid":
        state_file.write_text("{", encoding="utf-8")
        state_file.chmod(0o600)
    monkeypatch.setenv("CODEX_MASTER_MCP_STATE", str(state_directory))
    monkeypatch.delenv("CODEX_AGENT_MCP_STATE", raising=False)
    return state_directory


def configure_real_mutation_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_root = tmp_path / "server-state"
    monkeypatch.setattr(server, "STATE_ROOT", state_root)
    monkeypatch.setattr(server, "LOCK_DIR", state_root / "locks")


def queen_assignment_plan(*, mode: str = "enforced") -> object:
    return plan_queen_assignment(
        queen_id="queen-codex-master",
        dispatch_id="dispatch-one",
        workpackage={
            "workpackage_id": "workpackage-one",
            "repo_id": "codex-master",
            "teamlead_principal_id": "lead-one",
            "specialist_principal_id": "specialist-one",
            "writer_class_id": "spezialistin",
            "agent_id": "a1",
            "account_key": "sha256:" + "a" * 64,
            "model_id": "gpt-primary",
            "model_role": "primary",
            "task_complexity": "complex",
            "scope": ("src",),
            "write_paths": ("src/task.py",),
            "mode": mode,
            "pilot_enabled": True,
            "account_confirmed": True,
            "authority_verified": True,
            "repository_verified": True,
            "scope_verified": True,
            "lease_available": True,
            "selection_band": "none",
        },
    )


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


def test_server_lease_executor_rechecks_binding_and_routes_only_named_operations(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    materialize_probe_record(tmp_path, monkeypatch, "fresh-green")
    configure_real_mutation_lock(tmp_path, monkeypatch)
    seen: list[tuple[str, dict[str, object]]] = []
    lease = {"state": "unclaimed", "held_by_this_server": False, "lease_id": None}
    executor = build_server_lease_executor(
        operations={
            "hive_assignment_callback": lambda record, current: seen.append((record.admission_id, dict(current))) or {"status": "ok"},
        },
        lease_reader=lambda _agent: lease,
    )
    result = executor(executing_record(), "hive_assignment_callback")

    assert result == {"status": "ok"}
    assert seen == [("adm-runtime", lease)]
    with pytest.raises(AgentError, match="lease_operation_not_allowed"):
        executor(executing_record(), "hive_assignment_process_start")


def test_server_lease_executor_composes_with_runtime_revalidation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    materialize_probe_record(tmp_path, monkeypatch, "fresh-green")
    configure_real_mutation_lock(tmp_path, monkeypatch)
    executor = build_server_lease_executor(
        operations={"hive_assignment_callback": lambda _record, lease: {"lease_state": lease["state"]}},
        lease_reader=lambda _agent: {"state": "unclaimed", "held_by_this_server": False, "lease_id": None},
    )
    runtime = ServerAdmissionRuntime(allow_all([]), execute=executor, now=lambda: NOW)
    assert runtime.revalidate(revalidating_record()) is True

    assert runtime.execute(executing_record(), "hive_assignment_callback") == {"lease_state": "unclaimed"}


def test_server_lease_executor_rechecks_after_its_mutation_lock(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen: list[str] = []
    materialize_probe_record(tmp_path, monkeypatch, "fresh-green")
    configure_real_mutation_lock(tmp_path, monkeypatch)
    actual_mutation_lock = server.agent_lifecycle_lock

    @contextlib.contextmanager
    def mutation_lock(agent: str):
        with actual_mutation_lock(agent):
            seen.append("mutation-lock")
            failures: list[BaseException] = []

            def publish_red() -> None:
                try:
                    materialize_probe_record(tmp_path, monkeypatch, "red")
                except BaseException as exc:
                    failures.append(exc)

            writer = threading.Thread(target=publish_red)
            writer.start()
            writer.join(timeout=1)
            assert not writer.is_alive()
            assert failures == []
            yield

    monkeypatch.setattr(server, "agent_lifecycle_lock", mutation_lock)
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
    ("probe_state", "allowed"),
    (
        ("fresh-green", True),
        ("missing", False),
        ("invalid", False),
        ("stale", False),
        ("red", False),
        ("shadow", False),
        ("disabled", False),
    ),
)
@pytest.mark.parametrize("operation", sorted(server.HIVE_ASSIGNMENT_CAPACITY_SINKS))
def test_each_hive_capacity_sink_accepts_only_an_actual_fresh_green_record(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    probe_state: str,
    allowed: bool,
    operation: str,
) -> None:
    materialize_probe_record(tmp_path, monkeypatch, probe_state)
    configure_real_mutation_lock(tmp_path, monkeypatch)
    callback_calls: list[str] = []
    executor = build_server_lease_executor(
        operations={
            operation: lambda *_args: callback_calls.append(operation)
            or {"status": "started"}
        },
        lease_reader=lambda _agent: {"state": "unclaimed", "held_by_this_server": False, "lease_id": None},
    )

    if allowed:
        assert executor(executing_record(), operation) == {"status": "started"}
    else:
        with pytest.raises(AgentError, match="hive_spawn_probe_blocked"):
            executor(executing_record(), operation)

    assert callback_calls == ([operation] if allowed else [])


@pytest.mark.parametrize("operation", sorted(server.HIVE_ASSIGNMENT_CAPACITY_SINKS))
def test_each_hive_assignment_capacity_sink_waits_for_the_real_shared_probe_lock(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, operation: str
) -> None:
    state_directory = materialize_probe_record(tmp_path, monkeypatch, "fresh-green")
    configure_real_mutation_lock(tmp_path, monkeypatch)
    callback_called = threading.Event()
    completed = threading.Event()
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


@pytest.mark.parametrize(
    ("probe_state", "allowed"),
    (
        ("fresh-green", True),
        ("missing", False),
        ("invalid", False),
        ("stale", False),
        ("red", False),
        ("shadow", False),
        ("disabled", False),
    ),
)
@pytest.mark.parametrize("operation", sorted(server.QUEEN_ASSIGNMENT_CAPACITY_SINKS))
def test_each_queen_capacity_sink_accepts_only_an_actual_fresh_green_record(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    probe_state: str,
    allowed: bool,
    operation: str,
) -> None:
    materialize_probe_record(tmp_path, monkeypatch, probe_state)
    configure_real_mutation_lock(tmp_path, monkeypatch)
    callback_calls: list[str] = []
    step = operation.removeprefix("queen_assignment_")
    plan = type("Plan", (), {"agent_id": "a1"})()

    if allowed:
        assert server._execute_server_queen_assignment_capacity_sink(
            step, lambda _plan: callback_calls.append(operation) or {"status": "started"}, plan
        ) == {"status": "started"}
    else:
        with pytest.raises(AgentError, match="hive_spawn_probe_blocked"):
            server._execute_server_queen_assignment_capacity_sink(
                step, lambda _plan: callback_calls.append(operation) or {"status": "unexpected"}, plan
            )

    assert callback_calls == ([operation] if allowed else [])


@pytest.mark.parametrize("operation", sorted(server.QUEEN_ASSIGNMENT_CAPACITY_SINKS))
def test_each_queen_capacity_sink_waits_for_the_real_shared_probe_lock(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, operation: str
) -> None:
    state_directory = materialize_probe_record(tmp_path, monkeypatch, "fresh-green")
    configure_real_mutation_lock(tmp_path, monkeypatch)
    callback_called = threading.Event()
    completed = threading.Event()
    step = operation.removeprefix("queen_assignment_")

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


def test_server_queen_enforced_forward_steps_use_only_real_named_capacity_sinks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    materialize_probe_record(tmp_path, monkeypatch, "fresh-green")
    configure_real_mutation_lock(tmp_path, monkeypatch)
    events: list[str] = []
    context = server.build_server_queen_assignment_context(
        confirmed_accounts={"sha256:" + "a" * 64},
        primary_models={"gpt-primary"},
        create_teamlead_principal=lambda _plan: events.append("teamlead") or "lead",
        create_specialist_principal=lambda _plan: events.append("specialist") or "specialist",
        issue_grant=lambda _plan: events.append("grant") or "grant",
        reserve_admission=lambda _plan: events.append("admission") or "admission",
        execute_assignment=lambda _plan: events.append("assignment") or {"status": "started"},
        compensate=lambda name, *_args: events.append(f"compensate:{name}"),
    )

    result = server._execute_server_queen_assignment(queen_assignment_plan(), context)

    assert result["reason_code"] == "assignment_executed"
    assert events == ["teamlead", "specialist", "grant", "admission", "assignment"]


def test_server_queen_shadow_and_red_compensation_stay_outside_capacity_sinks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    materialize_probe_record(tmp_path, monkeypatch, "red")
    configure_real_mutation_lock(tmp_path, monkeypatch)
    events: list[str] = []
    context = server.build_server_queen_assignment_context(
        confirmed_accounts={"sha256:" + "a" * 64},
        primary_models={"gpt-primary"},
        create_teamlead_principal=lambda _plan: events.append("teamlead"),
        create_specialist_principal=lambda _plan: events.append("specialist"),
        issue_grant=lambda _plan: events.append("grant"),
        reserve_admission=lambda _plan: events.append("admission"),
        execute_assignment=lambda _plan: events.append("assignment") or {"status": "unexpected"},
        compensate=lambda name, *_args: events.append(f"compensate:{name}"),
    )

    shadow = server._execute_server_queen_assignment(
        queen_assignment_plan(mode="shadow"), context
    )
    red = server._execute_server_queen_assignment(queen_assignment_plan(), context)

    assert shadow["reason_code"] == "shadow_only"
    assert red["reason_code"] == "assignment_transaction_failed"
    assert events == ["compensate:teamlead"]


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
