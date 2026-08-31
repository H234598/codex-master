"""Closed restart-safe adapter from host-agent refs to local Ollama APIs."""

from __future__ import annotations

from collections.abc import Mapping
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import threading
import time
from typing import Any, Protocol, cast

from codex_master.hive.state import HiveStateError, HiveStateStore
from codex_master.ollama_registry import (
    OllamaInstanceV1,
    OllamaRegistryStore,
    OllamaRegistryV1,
)
from codex_master.ollama_runtime import (
    OllamaLocalPlan,
    OllamaRuntime,
    OllamaRuntimeError,
    RunningOllamaInstance,
    adopt_running_instance,
    ollama_plan_digest,
    plan_local_instance,
    probe_instance_readiness,
    probe_ollama_host,
    start_local_instance,
    stop_local_instance,
)


MAX_AGENT_OLLAMA_PLANS = 1024
MAX_AGENT_OLLAMA_JOURNAL_BYTES = 1024 * 1024
PLAN_MAX_AGE_SECONDS = 3600
_DOCUMENT = PurePosixPath("ollama-adapter.json")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_PLAN_REF = re.compile(r"plan-[0-9a-f]{32}\Z", re.ASCII)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z", re.ASCII)
_UNIT = re.compile(r"codex-master-ollama-[0-9a-f]{32}\.scope\Z", re.ASCII)
_MAX_INT = 2**63 - 1
_BOOT_ID = re.compile(r"[0-9a-f-]{36}\Z", re.ASCII)


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
            type(item) is not int or not 0 <= item <= _MAX_INT
        ):
            _fail("host.arguments_invalid")
    return document


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


class AgentOllamaOperations(Protocol):
    def plan(self, arguments: Mapping[str, object]) -> Mapping[str, object]: ...
    def apply(self, arguments: Mapping[str, object]) -> Mapping[str, object]: ...
    def probe(self, arguments: Mapping[str, object]) -> Mapping[str, object]: ...
    def stop(self, arguments: Mapping[str, object]) -> Mapping[str, object]: ...


class ProductionAgentOllamaAdapter:
    """Persist bounded plan identities and strongly recover running scopes."""

    def __init__(
        self,
        registry: OllamaRegistryStore,
        *,
        state_root: Path,
        runtime: OllamaRuntime | None = None,
        max_plans: int = MAX_AGENT_OLLAMA_PLANS,
        plan_max_age_seconds: int = PLAN_MAX_AGE_SECONDS,
    ) -> None:
        if (
            not isinstance(registry, OllamaRegistryStore)
            or not isinstance(state_root, Path)
            or not state_root.is_absolute()
            or type(max_plans) is not int
            or not 1 <= max_plans <= MAX_AGENT_OLLAMA_PLANS
            or type(plan_max_age_seconds) is not int
            or not 1 <= plan_max_age_seconds <= PLAN_MAX_AGE_SECONDS
        ):
            _fail("provider.registry_invalid")
        self._registry = registry
        self._runtime = runtime
        self._max_plans = max_plans
        self._plan_max_age = plan_max_age_seconds
        self._state = HiveStateStore(state_root / "host-agent-ollama")
        try:
            with self._state.locked():
                self._write_locked(self._read_locked())
        except (HiveStateError, OSError, ValueError):
            _fail("provider.journal_unavailable")

    def plan(self, arguments: Mapping[str, object]) -> Mapping[str, object]:
        instance_ref = cast(str, arguments["instance_ref"])
        generation = cast(int, arguments["generation"])
        registry, plan = self._fresh_plan(instance_ref, generation)
        del registry
        plan_ref = f"plan-{secrets.token_hex(16)}"
        now = int(time.time())
        with self._state.locked():
            document = self._read_locked()
            self._expire_plans(document, now=now, generation=generation)
            if len(document["plans"]) >= self._max_plans:
                _fail("provider.plan_limit")
            document["plans"][plan_ref] = {
                "instance_ref": instance_ref,
                "generation": generation,
                "plan_digest": ollama_plan_digest(plan),
                "created_at": now,
                "state": "ready",
                "claim": None,
            }
            self._write_locked(document)
        return {"plan_ref": plan_ref}

    def apply(self, arguments: Mapping[str, object]) -> Mapping[str, object]:
        plan_ref = cast(str, arguments["plan_ref"])
        with self._state.locked():
            preview = self._read_locked()["plans"].get(plan_ref)
        if preview is not None:
            self._reap_dead_running(cast(str, preview["instance_ref"]))
        with self._state.locked():
            document = self._read_locked()
            self._expire_plans(document, now=int(time.time()), generation=None)
            saved = document["plans"].get(plan_ref)
            if saved is None:
                _no_effect("provider.plan_missing")
            instance_ref = saved["instance_ref"]
            if instance_ref in document["running"]:
                _no_effect("provider.instance_already_running")
            if any(
                ref != plan_ref
                and value["instance_ref"] == instance_ref
                and value["state"] == "starting"
                and self._claim_alive(value["claim"])
                for ref, value in document["plans"].items()
            ):
                _no_effect("provider.instance_already_running")
            if saved["state"] != "ready":
                _no_effect("provider.instance_starting")
            saved["state"] = "starting"
            saved["claim"] = self._claim()
            self._write_locked(document)
        try:
            _registry, plan = self._fresh_plan(instance_ref, saved["generation"])
            if ollama_plan_digest(plan) != saved["plan_digest"]:
                _no_effect("provider.plan_changed")
            running = start_local_instance(plan, runtime=self._runtime)
        except Exception:
            with self._state.locked():
                document = self._read_locked()
                current = document["plans"].get(plan_ref)
                if current is not None and current["state"] == "starting":
                    current["state"] = "ready"
                    current["claim"] = None
                    self._write_locked(document)
            raise
        conflict = False
        with self._state.locked():
            document = self._read_locked()
            current = document["plans"].get(plan_ref)
            if current != saved:
                conflict = True
            else:
                del document["plans"][plan_ref]
                document["running"][instance_ref] = {
                    "generation": saved["generation"],
                    "plan_digest": saved["plan_digest"],
                    "unit_name": running.unit_name,
                    "port": running.port,
                    "ollama_pid": running.ollama_pid,
                    "control_group": running.control_group,
                    "process_start_ticks": running.process_start_ticks,
                }
                self._write_locked(document)
        if conflict:
            stop_local_instance(running, runtime=self._runtime)
            _fail("provider.journal_conflict")
        return {"instance_ref": instance_ref, "generation": saved["generation"]}

    def probe(self, arguments: Mapping[str, object]) -> Mapping[str, object]:
        running = self._running_instance(
            cast(str, arguments["instance_ref"]), cast(int, arguments["generation"])
        )
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
        with self._state.locked():
            document = self._read_locked()
            current = document["running"].get(instance_ref)
            if (
                current is None
                or current["generation"] != generation
                or current["unit_name"] != running.unit_name
                or current["ollama_pid"] != running.ollama_pid
            ):
                _fail("provider.journal_conflict")
            del document["running"][instance_ref]
            self._write_locked(document)
        return {"stopped": True}

    def _fresh_plan(
        self, instance_ref: str, generation: int
    ) -> tuple[OllamaRegistryV1, OllamaLocalPlan]:
        registry = self._load_generation(generation)
        instance = self._local_instance(registry, instance_ref)
        return registry, plan_local_instance(
            instance, probe_ollama_host(runtime=self._runtime), registry=registry
        )

    def _running_instance(
        self, instance_ref: str, generation: int
    ) -> RunningOllamaInstance:
        with self._state.locked():
            saved = self._read_locked()["running"].get(instance_ref)
        if saved is None:
            _no_effect("provider.instance_missing")
        if saved["generation"] != generation:
            _no_effect("provider.generation_stale")
        _registry, plan = self._fresh_plan(instance_ref, generation)
        if ollama_plan_digest(plan) != saved["plan_digest"]:
            _no_effect("provider.plan_changed")
        return adopt_running_instance(plan, runtime=self._runtime, **{
            key: saved[key]
            for key in (
                "unit_name", "port", "ollama_pid", "control_group",
                "process_start_ticks",
            )
        })

    def _reap_dead_running(self, instance_ref: str) -> None:
        with self._state.locked():
            saved = self._read_locked()["running"].get(instance_ref)
        if saved is None:
            return
        try:
            _registry, plan = self._fresh_plan(instance_ref, saved["generation"])
            if ollama_plan_digest(plan) != saved["plan_digest"]:
                return
            adopt_running_instance(plan, runtime=self._runtime, **{
                key: saved[key]
                for key in (
                    "unit_name", "port", "ollama_pid", "control_group",
                    "process_start_ticks",
                )
            })
            return
        except OllamaRuntimeError as error:
            if str(error) != "provider.process_unavailable":
                return
        with self._state.locked():
            document = self._read_locked()
            if document["running"].get(instance_ref) == saved:
                del document["running"][instance_ref]
                self._write_locked(document)

    def _load_generation(self, generation: int) -> OllamaRegistryV1:
        registry = self._registry.load()
        if registry.generation != generation:
            _no_effect("provider.generation_stale")
        return registry

    @staticmethod
    def _local_instance(registry: OllamaRegistryV1, instance_ref: str) -> OllamaInstanceV1:
        matches = [
            item for item in registry.instances
            if item.ref == instance_ref and item.host_ref == "local"
        ]
        if len(matches) != 1:
            _no_effect("provider.instance_missing")
        return matches[0]

    def _expire_plans(
        self, document: dict[str, Any], *, now: int, generation: int | None
    ) -> None:
        expired = sorted(
            ref for ref, value in document["plans"].items()
            if (
                value["state"] == "ready" and (
                    now - value["created_at"] >= self._plan_max_age
                    or (generation is not None and value["generation"] != generation)
                )
            ) or (
                value["state"] == "starting"
                and now - value["created_at"] >= self._plan_max_age
                and not self._claim_alive(value["claim"])
            )
        )
        for ref in expired:
            del document["plans"][ref]

    def _read_locked(self) -> dict[str, Any]:
        try:
            raw = self._state.read_private_bytes(
                _DOCUMENT, max_bytes=MAX_AGENT_OLLAMA_JOURNAL_BYTES
            )
        except HiveStateError as error:
            if str(error) == "state_not_found":
                return {"schema_version": 1, "plans": {}, "running": {}}
            _fail("provider.journal_unavailable")
        try:
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
        except (UnicodeError, ValueError, TypeError, RecursionError):
            _fail("provider.journal_unavailable")
        if (
            type(value) is not dict
            or set(value) != {"schema_version", "plans", "running"}
            or value["schema_version"] != 1
            or type(value["plans"]) is not dict
            or type(value["running"]) is not dict
            or len(value["plans"]) > self._max_plans
            or len(value["running"]) > 64
        ):
            _fail("provider.journal_unavailable")
        for ref, item in value["plans"].items():
            if (
                type(ref) is not str or _PLAN_REF.fullmatch(ref) is None
                or type(item) is not dict
                or set(item) != {"instance_ref", "generation", "plan_digest", "created_at", "state", "claim"}
                or type(item["instance_ref"]) is not str
                or _TOKEN.fullmatch(item["instance_ref"]) is None
                or not self._integer(item["generation"])
                or type(item["plan_digest"]) is not str
                or _DIGEST.fullmatch(item["plan_digest"]) is None
                or not self._integer(item["created_at"])
                or item["state"] not in {"ready", "starting"}
                or not self._valid_claim(item["claim"], required=item["state"] == "starting")
            ):
                _fail("provider.journal_unavailable")
        for ref, item in value["running"].items():
            if (
                type(ref) is not str or _TOKEN.fullmatch(ref) is None
                or type(item) is not dict
                or set(item) != {"generation", "plan_digest", "unit_name", "port", "ollama_pid", "control_group", "process_start_ticks"}
                or not self._integer(item["generation"])
                or type(item["plan_digest"]) is not str
                or _DIGEST.fullmatch(item["plan_digest"]) is None
                or type(item["unit_name"]) is not str
                or _UNIT.fullmatch(item["unit_name"]) is None
                or not self._integer(item["port"], 1, 65535)
                or not self._integer(item["ollama_pid"], 1)
                or type(item["control_group"]) is not str
                or not item["control_group"].startswith("/")
                or "\n" in item["control_group"]
                or not self._integer(item["process_start_ticks"], 1)
            ):
                _fail("provider.journal_unavailable")
        return cast(dict[str, Any], value)

    @staticmethod
    def _integer(value: object, low: int = 0, high: int = _MAX_INT) -> bool:
        return type(value) is int and low <= value <= high

    @staticmethod
    def _process_start_ticks(pid: int) -> int | None:
        try:
            raw = Path(f"/proc/{pid}/stat").read_bytes()
            fields = raw[raw.rfind(b")") + 2 :].split()
            value = int(fields[19])
            return value if value >= 1 else None
        except (OSError, ValueError, IndexError):
            return None

    @staticmethod
    def _boot_id() -> str:
        try:
            value = Path("/proc/sys/kernel/random/boot_id").read_text("ascii").strip()
        except OSError:
            _fail("provider.journal_unavailable")
        if _BOOT_ID.fullmatch(value) is None:
            _fail("provider.journal_unavailable")
        return value

    def _claim(self) -> dict[str, object]:
        start_ticks = self._process_start_ticks(os.getpid())
        if start_ticks is None:
            _fail("provider.journal_unavailable")
        return {
            "boot_id": self._boot_id(),
            "pid": os.getpid(),
            "process_start_ticks": start_ticks,
            "thread_id": threading.get_native_id(),
        }

    def _claim_alive(self, value: object) -> bool:
        if not self._valid_claim(value, required=True):
            return False
        claim = cast(dict[str, object], value)
        pid = cast(int, claim["pid"])
        return (
            claim["boot_id"] == self._boot_id()
            and self._process_start_ticks(pid) == claim["process_start_ticks"]
            and Path(f"/proc/{pid}/task/{claim['thread_id']}").is_dir()
        )

    def _valid_claim(self, value: object, *, required: bool) -> bool:
        if value is None:
            return not required
        return (
            type(value) is dict
            and set(value) == {"boot_id", "pid", "process_start_ticks", "thread_id"}
            and type(value["boot_id"]) is str
            and _BOOT_ID.fullmatch(value["boot_id"]) is not None
            and self._integer(value["pid"], 1)
            and self._integer(value["process_start_ticks"], 1)
            and self._integer(value["thread_id"], 1)
        )

    def _write_locked(self, document: Mapping[str, object]) -> None:
        encoded = json.dumps(
            document, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("ascii") + b"\n"
        if len(encoded) > MAX_AGENT_OLLAMA_JOURNAL_BYTES:
            _fail("provider.journal_unavailable")
        self._state.replace_private_bytes(_DOCUMENT, encoded)


class AgentOllamaExecutor:
    def __init__(self, operations: AgentOllamaOperations) -> None:
        self._operations = operations

    def validate(self, action: str, value: object) -> dict[str, object]:
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
        return dict(self._operations.plan(self.validate("plan", value)))

    def apply(self, value: object) -> dict[str, object]:
        return dict(self._operations.apply(self.validate("apply", value)))

    def probe(self, value: object) -> dict[str, object]:
        return dict(self._operations.probe(self.validate("probe", value)))

    def stop(self, value: object) -> dict[str, object]:
        return dict(self._operations.stop(self.validate("stop", value)))


__all__ = [
    "AgentOllamaError", "AgentOllamaExecutor", "AgentOllamaNoEffectError",
    "AgentOllamaOperations", "MAX_AGENT_OLLAMA_PLANS",
    "ProductionAgentOllamaAdapter",
]
