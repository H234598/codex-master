from __future__ import annotations

from pathlib import Path
import re

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
from codex_master.ollama_runtime import OllamaRuntimeError


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

    def cleanup_scope(self, request: object, process: object) -> None:
        return None

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
        agent_ollama.ProductionAgentOllamaAdapter(store, runtime=runtime)
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


def test_apply_revalidates_original_path_evidence_at_actual_consumer(
    tmp_path: Path,
) -> None:
    store, executable = registry_at(tmp_path)
    runtime = ControlledRuntime()
    executor = AgentOllamaExecutor(
        agent_ollama.ProductionAgentOllamaAdapter(store, runtime=runtime)
    )
    plan_ref = executor.plan(
        {"instance_ref": "instance-one", "generation": 1}
    )["plan_ref"]
    executable.rename(tmp_path / "old-ollama")
    executable.write_bytes(b"#!/bin/sh\nexit 0\n")
    executable.chmod(0o700)

    with pytest.raises(OllamaRuntimeError, match="resource.target_path_changed"):
        executor.apply({"plan_ref": plan_ref})

    assert runtime.started == []


def test_unknown_or_stale_local_refs_prove_no_effect(tmp_path: Path) -> None:
    store, _executable = registry_at(tmp_path)
    executor = AgentOllamaExecutor(
        agent_ollama.ProductionAgentOllamaAdapter(
            store, runtime=ControlledRuntime()
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
            store, runtime=ControlledRuntime()
        )
    )
    with pytest.raises(AgentOllamaError, match="host.arguments_invalid"):
        executor.apply({"plan_ref": "one", "free": "form"})
    with pytest.raises(AgentOllamaError, match="host.arguments_invalid"):
        executor.probe({"instance_ref": "/absolute/path", "generation": 1})
