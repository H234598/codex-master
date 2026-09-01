from __future__ import annotations

from pathlib import Path
import multiprocessing
import re
import threading

import pytest

from codex_master import agent_ollama
from codex_master.agent_ollama import (
    AgentOllamaError,
    AgentOllamaExecutor,
)
from codex_master.ollama_registry import (
    OllamaInstanceV1,
    OllamaModelV1,
    OllamaRegistryStore,
)


class FakeProcess:
    pid = 4242

    def poll(self) -> int | None:
        return None

    def wait(self, timeout: float | None = None) -> int:
        return 0


class ControlledRuntime:
    def __init__(self) -> None:
        self.started: list[object] = []
        self.stopped: list[object] = []
        self.process_up = True
        self.identity_status: str | None = None

    def available_cpus(self) -> tuple[int, ...]:
        return (0,)

    def allocate_loopback_port(self) -> int:
        return 11435

    def start_scope(self, request: object) -> FakeProcess:
        self.started.append(request)
        return FakeProcess()

    def resolve_scope(
        self, request: object, process: object
    ) -> tuple[int, str, int]:
        return 4343, "/user.slice/ollama.scope", 901

    def process_running(
        self, process: object, pid: int, start_ticks: int
    ) -> bool:
        return self.process_up

    def scope_process_matches(
        self,
        unit_name: str,
        pid: int,
        control_group: str,
        start_ticks: int,
    ) -> bool:
        return True

    def listener_owned_by(self, pid: int, port: int) -> bool:
        return True

    def classify_running_identity(
        self, unit_name: str, pid: int, control_group: str,
        start_ticks: int, port: int, executable: object,
    ) -> str:
        return self.identity_status or ("exact" if self.process_up else "absent")

    def recover_start_intent(
        self, unit_name: str, port: int, executable: object
    ) -> tuple[str, int | None, str | None, int | None]:
        if not self.started or not self.process_up:
            return "absent", None, None, None
        return "exact", 4343, "/user.slice/ollama.scope", 901

    def fetch_tags(
        self,
        pid: int,
        port: int,
        *,
        unit_name: str,
        control_group: str,
        start_ticks: int,
        timeout_seconds: float,
        max_bytes: int,
    ) -> set[str]:
        return {"model-id"}

    def cleanup_scope(self, request: object, process: object) -> bool:
        return True

    def stop_scope(self, request: object) -> None:
        self.stopped.append(request)
        self.process_up = False


def registry_at(tmp_path: Path) -> tuple[OllamaRegistryStore, Path]:
    executable = tmp_path / "ollama"
    executable.write_bytes(b"#!/bin/sh\nexit 0\n")
    executable.chmod(0o700)
    models = tmp_path / "models"
    models.mkdir(mode=0o700)
    store = OllamaRegistryStore.for_test(tmp_path / "registry")
    store.replace(
        models=(
            OllamaModelV1(
                "model",
                "model-id",
                True,
                True,
                True,
                None,
            ),
        ),
        instances=(
            OllamaInstanceV1(
                "instance-one",
                "Instance One",
                "local",
                str(executable),
                str(models),
                ("model",),
                "0",
                100,
                100,
                "planned",
                "unknown",
            ),
        ),
        expected_generation=0,
    )
    return store, executable


def test_production_adapter_uses_public_runtime_plan_apply_probe_stop(
    tmp_path: Path,
) -> None:
    store, _executable = registry_at(tmp_path)
    runtime = ControlledRuntime()
    executor = AgentOllamaExecutor(
        agent_ollama.ProductionAgentOllamaAdapter(
            store, state_root=tmp_path / "state", runtime=runtime
        )
    )

    planned = executor.plan({"instance_ref": "instance-one", "generation": 1})
    assert re.fullmatch(r"plan-[0-9a-f]{32}", planned["plan_ref"])
    applied = executor.apply({"plan_ref": planned["plan_ref"]})
    assert applied == {"instance_ref": "instance-one", "generation": 1}
    assert len(runtime.started) == 1

    probed = executor.probe({"instance_ref": "instance-one", "generation": 1})
    assert probed == {
        "ready": True,
        "reason_codes": [],
        "process_running": True,
        "cgroup_member": True,
        "loopback_endpoint_reachable": True,
        "available_model_ids": ["model-id"],
    }
    assert executor.stop(
        {"instance_ref": "instance-one", "generation": 1}
    ) == {"stopped": True}
    assert len(runtime.stopped) == 1


def test_default_port_allocator_uses_system_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class DefaultRuntime:
        def allocate_loopback_port(self) -> int:
            return 11436

    monkeypatch.setattr(
        "codex_master.ollama_runtime.SystemOllamaRuntime",
        lambda: DefaultRuntime(),
    )
    store, _executable = registry_at(tmp_path)
    adapter = agent_ollama.ProductionAgentOllamaAdapter(
        store, state_root=tmp_path / "state"
    )

    assert adapter._allocate_port() == 11436


def test_apply_revalidates_original_path_evidence_at_actual_consumer(
    tmp_path: Path,
) -> None:
    store, executable = registry_at(tmp_path)
    runtime = ControlledRuntime()
    executor = AgentOllamaExecutor(
        agent_ollama.ProductionAgentOllamaAdapter(
            store, state_root=tmp_path / "state", runtime=runtime
        )
    )
    plan_ref = executor.plan(
        {"instance_ref": "instance-one", "generation": 1}
    )["plan_ref"]
    executable.rename(tmp_path / "old-ollama")
    executable.write_bytes(b"#!/bin/sh\nexit 0\n")
    executable.chmod(0o700)

    with pytest.raises(
        agent_ollama.AgentOllamaNoEffectError, match="provider.plan_changed"
    ):
        executor.apply({"plan_ref": plan_ref})

    assert runtime.started == []


def test_agent_executor_rejects_apply_when_durable_plan_precondition_drifts(
    tmp_path: Path,
) -> None:
    store, _executable = registry_at(tmp_path)
    runtime = ControlledRuntime()
    executor = AgentOllamaExecutor(
        agent_ollama.ProductionAgentOllamaAdapter(
            store, state_root=tmp_path / "state", runtime=runtime
        )
    )
    expected = "sha256:" + "a" * 64
    plan_ref = executor.plan(
        {"instance_ref": "instance-one", "generation": 1},
        plan_precondition_digest=expected,
    )["plan_ref"]

    with pytest.raises(
        agent_ollama.AgentOllamaNoEffectError,
        match="provider.plan_precondition_stale",
    ):
        executor.apply(
            {"plan_ref": plan_ref},
            plan_precondition_digest="sha256:" + "b" * 64,
        )

    assert runtime.started == []


def test_agent_executor_rejects_apply_when_durable_resource_fence_drifts(
    tmp_path: Path,
) -> None:
    store, _executable = registry_at(tmp_path)
    runtime = ControlledRuntime()
    executor = AgentOllamaExecutor(
        agent_ollama.ProductionAgentOllamaAdapter(
            store, state_root=tmp_path / "state", runtime=runtime
        )
    )
    digest = "sha256:" + "a" * 64
    plan_ref = executor.plan(
        {"instance_ref": "instance-one", "generation": 1},
        plan_precondition_digest=digest,
        resource_generation=7,
    )["plan_ref"]

    with pytest.raises(
        agent_ollama.AgentOllamaNoEffectError,
        match="provider.resource_generation_stale",
    ):
        executor.apply(
            {"plan_ref": plan_ref},
            plan_precondition_digest=digest,
            resource_generation=8,
        )

    assert runtime.started == []


def test_unknown_or_stale_local_refs_prove_no_effect(tmp_path: Path) -> None:
    store, _executable = registry_at(tmp_path)
    executor = AgentOllamaExecutor(
        agent_ollama.ProductionAgentOllamaAdapter(
            store, state_root=tmp_path / "state", runtime=ControlledRuntime()
        )
    )
    with pytest.raises(
        agent_ollama.AgentOllamaNoEffectError, match="provider.plan_missing"
    ):
        executor.apply({"plan_ref": "plan-" + "0" * 32})
    with pytest.raises(
        agent_ollama.AgentOllamaNoEffectError,
        match="provider.instance_missing",
    ):
        executor.stop({"instance_ref": "missing", "generation": 1})
    with pytest.raises(
        agent_ollama.AgentOllamaNoEffectError,
        match="provider.generation_stale",
    ):
        executor.plan({"instance_ref": "instance-one", "generation": 0})


def test_each_closed_action_rejects_free_form_arguments(tmp_path: Path) -> None:
    store, _executable = registry_at(tmp_path)
    executor = AgentOllamaExecutor(
        agent_ollama.ProductionAgentOllamaAdapter(
            store, state_root=tmp_path / "state", runtime=ControlledRuntime()
        )
    )
    with pytest.raises(AgentOllamaError, match="host.arguments_invalid"):
        executor.apply({"plan_ref": "one", "free": "form"})
    with pytest.raises(AgentOllamaError, match="host.arguments_invalid"):
        executor.probe({"instance_ref": "/absolute/path", "generation": 1})


def test_adapter_restart_recovers_plan_and_running_ownership(tmp_path: Path) -> None:
    store, _executable = registry_at(tmp_path)
    runtime = ControlledRuntime()
    state_root = tmp_path / "state"
    first = AgentOllamaExecutor(
        agent_ollama.ProductionAgentOllamaAdapter(
            store, state_root=state_root, runtime=runtime
        )
    )
    plan_ref = first.plan(
        {"instance_ref": "instance-one", "generation": 1}
    )["plan_ref"]
    second = AgentOllamaExecutor(
        agent_ollama.ProductionAgentOllamaAdapter(
            store, state_root=state_root, runtime=runtime
        )
    )
    second.apply({"plan_ref": plan_ref})
    third = AgentOllamaExecutor(
        agent_ollama.ProductionAgentOllamaAdapter(
            store, state_root=state_root, runtime=runtime
        )
    )
    assert third.probe(
        {"instance_ref": "instance-one", "generation": 1}
    )["ready"] is True
    assert third.stop(
        {"instance_ref": "instance-one", "generation": 1}
    ) == {"stopped": True}


def test_plan_journal_has_exact_limit_and_deterministic_expiry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _executable = registry_at(tmp_path)
    now = 1_000
    monkeypatch.setattr(agent_ollama.time, "time", lambda: now)
    adapter = agent_ollama.ProductionAgentOllamaAdapter(
        store,
        state_root=tmp_path / "state",
        runtime=ControlledRuntime(),
        max_plans=2,
        plan_max_age_seconds=10,
    )
    arguments = {"instance_ref": "instance-one", "generation": 1}
    adapter.plan(arguments)
    adapter.plan(arguments)
    with pytest.raises(AgentOllamaError, match="provider.plan_limit"):
        adapter.plan(arguments)
    now = 1_010
    assert "plan_ref" in adapter.plan(arguments)


def test_concurrent_apply_consumes_one_durable_plan_once(tmp_path: Path) -> None:
    store, _executable = registry_at(tmp_path)
    runtime = ControlledRuntime()
    state_root = tmp_path / "state"
    first = agent_ollama.ProductionAgentOllamaAdapter(
        store, state_root=state_root, runtime=runtime
    )
    second = agent_ollama.ProductionAgentOllamaAdapter(
        store, state_root=state_root, runtime=runtime
    )
    arguments = {"instance_ref": "instance-one", "generation": 1}
    plan_refs = [
        first.plan(arguments)["plan_ref"],
        second.plan(arguments)["plan_ref"],
    ]
    barrier = threading.Barrier(3)
    outcomes: list[str] = []

    def apply(
        adapter: agent_ollama.ProductionAgentOllamaAdapter, plan_ref: str
    ) -> None:
        barrier.wait()
        try:
            adapter.apply({"plan_ref": plan_ref})
            outcomes.append("started")
        except agent_ollama.AgentOllamaNoEffectError:
            outcomes.append("rejected")

    threads = [
        threading.Thread(target=apply, args=(adapter, plan_ref))
        for adapter, plan_ref in zip((first, second), plan_refs, strict=True)
    ]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(3)
    assert sorted(outcomes) == ["rejected", "started"]
    assert len(runtime.started) == 1


def test_new_registry_generation_expires_old_plans(tmp_path: Path) -> None:
    store, _executable = registry_at(tmp_path)
    adapter = agent_ollama.ProductionAgentOllamaAdapter(
        store, state_root=tmp_path / "state", runtime=ControlledRuntime()
    )
    old_ref = adapter.plan(
        {"instance_ref": "instance-one", "generation": 1}
    )["plan_ref"]
    snapshot = store.load()
    store.replace(
        models=snapshot.models,
        instances=snapshot.instances,
        expected_generation=1,
    )
    adapter.plan({"instance_ref": "instance-one", "generation": 2})
    with pytest.raises(
        agent_ollama.AgentOllamaNoEffectError, match="provider.plan_missing"
    ):
        adapter.apply({"plan_ref": old_ref})


def test_hard_crash_after_start_recovers_durable_intent_without_second_start(
    tmp_path: Path,
) -> None:
    store, _executable = registry_at(tmp_path)

    class CrashOnce(ControlledRuntime):
        crashed = False

        def start_scope(self, request: object) -> FakeProcess:
            self.started.append(request)
            if not self.crashed:
                self.crashed = True
                raise SystemExit("hard crash")
            return FakeProcess()

    runtime = CrashOnce()
    state_root = tmp_path / "state"
    adapter = agent_ollama.ProductionAgentOllamaAdapter(
        store, state_root=state_root, runtime=runtime
    )
    plan_ref = adapter.plan(
        {"instance_ref": "instance-one", "generation": 1}
    )["plan_ref"]
    crashed: list[BaseException] = []

    def apply_and_crash() -> None:
        try:
            adapter.apply({"plan_ref": plan_ref})
        except BaseException as error:
            crashed.append(error)

    owner = threading.Thread(target=apply_and_crash)
    owner.start()
    owner.join(2)
    assert len(crashed) == 1 and isinstance(crashed[0], SystemExit)
    restarted = agent_ollama.ProductionAgentOllamaAdapter(
        store, state_root=state_root, runtime=runtime
    )
    assert restarted.apply({"plan_ref": plan_ref}) == {
        "instance_ref": "instance-one",
        "generation": 1,
    }
    assert len(runtime.started) == 1


def test_running_reconcile_handles_absence_conflict_advance_and_rollback(
    tmp_path: Path,
) -> None:
    store, _executable = registry_at(tmp_path)
    runtime = ControlledRuntime()
    state_root = tmp_path / "state"
    adapter = agent_ollama.ProductionAgentOllamaAdapter(
        store, state_root=state_root, runtime=runtime
    )
    executor = AgentOllamaExecutor(adapter)
    digest = "sha256:" + "a" * 64
    fences = {
        "plan_precondition_digest": digest,
        "resource_generation": 7,
    }
    plan_ref = executor.plan(
        {"instance_ref": "instance-one", "generation": 1}, **fences
    )["plan_ref"]
    executor.apply({"plan_ref": plan_ref}, **fences)
    snapshot = store.load()
    store.replace(
        models=snapshot.models,
        instances=snapshot.instances,
        expected_generation=1,
    )
    adapter.validate_running_precondition(
        "instance-one", 1, digest, 7
    )
    assert executor.probe(
        {"instance_ref": "instance-one", "generation": 2}, **fences
    )["ready"] is True
    with pytest.raises(
        agent_ollama.AgentOllamaNoEffectError,
        match="provider.generation_stale",
    ):
        executor.probe(
            {"instance_ref": "instance-one", "generation": 1}, **fences
        )
    with pytest.raises(
        agent_ollama.AgentOllamaNoEffectError,
        match="provider.generation_stale",
    ):
        adapter.probe({"instance_ref": "instance-one", "generation": 1})
    with pytest.raises(
        agent_ollama.AgentOllamaNoEffectError,
        match="provider.generation_stale",
    ):
        adapter.stop({"instance_ref": "instance-one", "generation": 1})
    assert runtime.stopped == []
    runtime.identity_status = "conflict"
    with pytest.raises(Exception, match="provider.instance_identity_conflict"):
        executor.stop(
            {"instance_ref": "instance-one", "generation": 2}, **fences
        )
    runtime.identity_status = "absent"
    assert executor.stop(
        {"instance_ref": "instance-one", "generation": 2}, **fences
    ) == {"stopped": True}
    assert runtime.stopped == []


def test_concurrent_stops_perform_at_most_one_runtime_effect(tmp_path: Path) -> None:
    store, _executable = registry_at(tmp_path)
    entered = threading.Event()
    release = threading.Event()

    class BlockingStop(ControlledRuntime):
        def stop_scope(self, request: object) -> None:
            self.stopped.append(request)
            entered.set()
            assert release.wait(2)
            self.process_up = False

    runtime = BlockingStop()
    state_root = tmp_path / "state"
    first = agent_ollama.ProductionAgentOllamaAdapter(
        store, state_root=state_root, runtime=runtime
    )
    plan_ref = first.plan(
        {"instance_ref": "instance-one", "generation": 1}
    )["plan_ref"]
    first.apply({"plan_ref": plan_ref})
    second = agent_ollama.ProductionAgentOllamaAdapter(
        store, state_root=state_root, runtime=runtime
    )
    outcomes: list[str] = []

    def stop(adapter: agent_ollama.ProductionAgentOllamaAdapter) -> None:
        try:
            adapter.stop({"instance_ref": "instance-one", "generation": 1})
            outcomes.append("stopped")
        except agent_ollama.AgentOllamaNoEffectError:
            outcomes.append("waiting")

    owner = threading.Thread(target=stop, args=(first,))
    competitor = threading.Thread(target=stop, args=(second,))
    owner.start()
    assert entered.wait(1)
    competitor.start()
    competitor.join(2)
    release.set()
    owner.join(2)
    competitor.join(2)
    assert not owner.is_alive() and not competitor.is_alive()
    assert sorted(outcomes) == ["stopped", "waiting"]
    assert len(runtime.stopped) == 1


def test_cross_process_stops_perform_at_most_one_runtime_effect(tmp_path: Path) -> None:
    store, _executable = registry_at(tmp_path)
    state_root = tmp_path / "state"
    setup_runtime = ControlledRuntime()
    setup = agent_ollama.ProductionAgentOllamaAdapter(
        store, state_root=state_root, runtime=setup_runtime
    )
    plan_ref = setup.plan(
        {"instance_ref": "instance-one", "generation": 1}
    )["plan_ref"]
    setup.apply({"plan_ref": plan_ref})
    context = multiprocessing.get_context("fork")
    count = context.Value("i", 0)
    entered = context.Event()
    release = context.Event()
    results = context.Queue()

    class ProcessRuntime(ControlledRuntime):
        def stop_scope(self, request: object) -> None:
            with count.get_lock():
                count.value += 1
            entered.set()
            release.wait(3)

    def stop() -> None:
        adapter = agent_ollama.ProductionAgentOllamaAdapter(
            store, state_root=state_root, runtime=ProcessRuntime()
        )
        try:
            adapter.stop({"instance_ref": "instance-one", "generation": 1})
            results.put("stopped")
        except agent_ollama.AgentOllamaNoEffectError:
            results.put("waiting")

    first = context.Process(target=stop)
    second = context.Process(target=stop)
    try:
        first.start()
        assert entered.wait(2)
        second.start()
        second.join(3)
        release.set()
        first.join(3)
        assert first.exitcode == 0 and second.exitcode == 0
        assert sorted((results.get(timeout=1), results.get(timeout=1))) == [
            "stopped",
            "waiting",
        ]
        assert count.value == 1
    finally:
        release.set()
        for process in (first, second):
            if process.pid is not None:
                process.join(1)
                if process.is_alive():
                    process.terminate()
                    process.join(2)
