"""Closed adapter from host-agent refs to hardened local Ollama APIs."""

from __future__ import annotations

from collections.abc import Mapping
import re
import secrets
import threading
from typing import Protocol, cast

from codex_master.ollama_registry import (
    OllamaInstanceV1,
    OllamaRegistryStore,
    OllamaRegistryV1,
)
from codex_master.ollama_runtime import (
    OllamaLocalPlan,
    OllamaRuntime,
    RunningOllamaInstance,
    plan_local_instance,
    probe_instance_readiness,
    probe_ollama_host,
    start_local_instance,
    stop_local_instance,
)


_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)


class AgentOllamaError(ValueError):
    """Code-only rejected Ollama operation."""


class AgentOllamaNoEffectError(AgentOllamaError):
    """Typed proof that a rejected mutating request performed no effect."""


def _fail(code: str) -> None:
    raise AgentOllamaError(code)


def _no_effect(code: str) -> None:
    raise AgentOllamaNoEffectError(code)


def _arguments(value: object, fields: frozenset[str]) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != fields:
        _fail("host.arguments_invalid")
    document = dict(cast(Mapping[str, object], value))
    for field, item in document.items():
        if field.endswith("_ref") and (
            type(item) is not str or _TOKEN.fullmatch(item) is None
        ):
            _fail("host.arguments_invalid")
        if field == "generation" and (
            type(item) is not int or not 0 <= item <= 2**63 - 1
        ):
            _fail("host.arguments_invalid")
    return document


class AgentOllamaOperations(Protocol):
    """Closed action surface consumed by the wire executor."""

    def plan(self, arguments: Mapping[str, object]) -> Mapping[str, object]: ...
    def apply(self, arguments: Mapping[str, object]) -> Mapping[str, object]: ...
    def probe(self, arguments: Mapping[str, object]) -> Mapping[str, object]: ...
    def stop(self, arguments: Mapping[str, object]) -> Mapping[str, object]: ...


class ProductionAgentOllamaAdapter:
    """Resolve bounded refs into existing public Ollama runtime objects."""

    def __init__(
        self,
        registry: OllamaRegistryStore,
        *,
        runtime: OllamaRuntime | None = None,
    ) -> None:
        if not isinstance(registry, OllamaRegistryStore):
            _fail("provider.registry_invalid")
        self._registry = registry
        self._runtime = runtime
        self._lock = threading.RLock()
        self._plans: dict[str, tuple[int, OllamaLocalPlan]] = {}
        self._running: dict[str, tuple[int, RunningOllamaInstance]] = {}
        self._starting: set[str] = set()

    def plan(self, arguments: Mapping[str, object]) -> Mapping[str, object]:
        instance_ref = cast(str, arguments["instance_ref"])
        generation = cast(int, arguments["generation"])
        registry = self._load_generation(generation)
        instance = self._local_instance(registry, instance_ref)
        plan = plan_local_instance(
            instance,
            probe_ollama_host(runtime=self._runtime),
            registry=registry,
        )
        plan_ref = f"plan-{secrets.token_hex(16)}"
        with self._lock:
            self._plans[plan_ref] = (generation, plan)
        return {"plan_ref": plan_ref}

    def apply(self, arguments: Mapping[str, object]) -> Mapping[str, object]:
        plan_ref = cast(str, arguments["plan_ref"])
        with self._lock:
            saved = self._plans.pop(plan_ref, None)
            if saved is None:
                _no_effect("provider.plan_missing")
            generation, plan = saved
            instance_ref = plan.instance.ref
            if instance_ref in self._running or instance_ref in self._starting:
                _no_effect("provider.instance_already_running")
            self._starting.add(instance_ref)
        try:
            current = self._load_generation(generation)
            self._local_instance(current, instance_ref)
            running = start_local_instance(plan, runtime=self._runtime)
        except Exception:
            with self._lock:
                self._starting.discard(instance_ref)
            raise
        with self._lock:
            self._starting.remove(instance_ref)
            self._running[instance_ref] = (generation, running)
        return {"instance_ref": instance_ref, "generation": generation}

    def probe(self, arguments: Mapping[str, object]) -> Mapping[str, object]:
        instance_ref = cast(str, arguments["instance_ref"])
        generation = cast(int, arguments["generation"])
        running = self._running_instance(instance_ref, generation)
        status = probe_instance_readiness(running, runtime=self._runtime)
        return {
            "ready": status.ready,
            "reason_codes": list(status.reason_codes),
            "process_running": status.process_running,
            "cgroup_member": status.cgroup_member,
            "loopback_endpoint_reachable": status.loopback_endpoint_reachable,
            "available_model_ids": list(status.available_model_ids),
        }

    def stop(self, arguments: Mapping[str, object]) -> Mapping[str, object]:
        instance_ref = cast(str, arguments["instance_ref"])
        generation = cast(int, arguments["generation"])
        running = self._running_instance(instance_ref, generation)
        stop_local_instance(running, runtime=self._runtime)
        with self._lock:
            current = self._running.get(instance_ref)
            if current == (generation, running):
                del self._running[instance_ref]
        return {"stopped": True}

    def _load_generation(self, generation: int) -> OllamaRegistryV1:
        registry = self._registry.load()
        if registry.generation != generation:
            _no_effect("provider.generation_stale")
        return registry

    @staticmethod
    def _local_instance(
        registry: OllamaRegistryV1, instance_ref: str
    ) -> OllamaInstanceV1:
        matches = [
            instance
            for instance in registry.instances
            if instance.ref == instance_ref and instance.host_ref == "local"
        ]
        if len(matches) != 1:
            _no_effect("provider.instance_missing")
        return matches[0]

    def _running_instance(
        self, instance_ref: str, generation: int
    ) -> RunningOllamaInstance:
        with self._lock:
            saved = self._running.get(instance_ref)
        if saved is None:
            _no_effect("provider.instance_missing")
        saved_generation, running = saved
        if saved_generation != generation:
            _no_effect("provider.generation_stale")
        return running


class AgentOllamaExecutor:
    """Exact per-action parsers in front of the production adapter."""

    def __init__(self, operations: AgentOllamaOperations) -> None:
        self._operations = operations

    def validate(self, action: str, value: object) -> dict[str, object]:
        """Validate an action payload without crossing its effect boundary."""
        fields = {
            "plan": frozenset({"instance_ref", "generation"}),
            "apply": frozenset({"plan_ref"}),
            "probe": frozenset({"instance_ref", "generation"}),
            "stop": frozenset({"instance_ref", "generation"}),
        }.get(action)
        if fields is None:
            _fail("host.action_unsupported")
        return _arguments(value, fields)

    def plan(self, value: object) -> dict[str, object]:
        """Plan through the existing path-evidence runtime."""
        return dict(self._operations.plan(self.validate("plan", value)))

    def apply(self, value: object) -> dict[str, object]:
        """Start one validated plan reference."""
        return dict(self._operations.apply(self.validate("apply", value)))

    def probe(self, value: object) -> dict[str, object]:
        """Probe one running local instance."""
        return dict(self._operations.probe(self.validate("probe", value)))

    def stop(self, value: object) -> dict[str, object]:
        """Stop one running local instance."""
        return dict(self._operations.stop(self.validate("stop", value)))


__all__ = [
    "AgentOllamaError",
    "AgentOllamaExecutor",
    "AgentOllamaNoEffectError",
    "AgentOllamaOperations",
    "ProductionAgentOllamaAdapter",
]
