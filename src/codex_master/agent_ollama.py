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
    OllamaStartError,
    RunningOllamaInstance,
    adopt_running_instance,
    ollama_plan_digest,
    plan_local_instance,
    probe_instance_readiness,
    probe_ollama_host,
    recover_started_instance,
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
        self._reap_absent_intents()
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
                "unit_name": None,
                "port": None,
                "queue_plan_digest": None,
                "queue_resource_generation": None,
            }
            self._write_locked(document)
        return {"plan_ref": plan_ref}

    def apply(self, arguments: Mapping[str, object]) -> Mapping[str, object]:
        plan_ref = cast(str, arguments["plan_ref"])
        self._reap_absent_intents(skip_ref=plan_ref)
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
                and value["state"] == "intent"
                for ref, value in document["plans"].items()
            ):
                _no_effect("provider.instance_already_running")
            if saved["state"] == "intent" and self._claim_alive(saved["claim"]):
                _no_effect("provider.instance_starting")
            created_intent = saved["state"] == "ready"
            if created_intent:
                saved["unit_name"] = (
                    f"codex-master-ollama-{secrets.token_hex(16)}.scope"
                )
                saved["port"] = (self._runtime.allocate_loopback_port()
                    if self._runtime is not None else self._allocate_port())
            saved["state"] = "intent"
            saved["claim"] = self._claim()
            self._write_locked(document)
        try:
            _registry, plan = self._fresh_plan_current(instance_ref)
            if ollama_plan_digest(plan) != saved["plan_digest"]:
                if created_intent:
                    self._reset_plan_intent(plan_ref, saved)
                _no_effect("provider.plan_changed")
            recovered = recover_started_instance(
                plan,
                unit_name=saved["unit_name"],
                port=saved["port"],
                runtime=self._runtime,
            )
            if recovered is not None:
                return self._commit_running(plan_ref, saved, recovered)
            _registry, plan = self._fresh_plan_current(instance_ref)
            if ollama_plan_digest(plan) != saved["plan_digest"]:
                if created_intent:
                    self._reset_plan_intent(plan_ref, saved)
                _no_effect("provider.plan_changed")
            running = start_local_instance(
                plan,
                runtime=self._runtime,
                unit_name=saved["unit_name"],
                port=saved["port"],
            )
        except OllamaStartError as error:
            if error.cleanup_proven:
                self._reset_plan_intent(plan_ref, saved)
            raise
        except Exception:
            raise
        try:
            return self._commit_running(plan_ref, saved, running)
        except Exception:
            try:
                stop_local_instance(running, runtime=self._runtime)
            except Exception:
                raise
            with self._state.locked():
                document = self._read_locked()
                current = document["plans"].get(plan_ref)
                if current == saved:
                    current.update(
                        state="ready", claim=None, unit_name=None, port=None
                    )
                    self._write_locked(document)
            raise

    def _commit_running(
        self,
        plan_ref: str,
        saved: dict[str, Any],
        running: RunningOllamaInstance,
    ) -> Mapping[str, object]:
        conflict = False
        instance_ref = saved["instance_ref"]
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
                    "state": "running",
                    "claim": None,
                    "queue_plan_digest": saved["queue_plan_digest"],
                    "queue_resource_generation": saved[
                        "queue_resource_generation"
                    ],
                }
                self._write_locked(document)
        if conflict:
            _fail("provider.journal_conflict")
        return {"instance_ref": instance_ref, "generation": saved["generation"]}

    def _allocate_port(self) -> int:
        from codex_master.ollama_runtime import SystemOllamaRuntime

        return SystemOllamaRuntime().allocate_loopback_port()

    def _reset_plan_intent(self, plan_ref: str, saved: Mapping[str, object]) -> None:
        with self._state.locked():
            document = self._read_locked()
            current = document["plans"].get(plan_ref)
            if current == saved:
                current.update(state="ready", claim=None, unit_name=None, port=None)
                self._write_locked(document)

    def bind_plan_precondition(
        self,
        plan_ref: str,
        plan_digest: object,
        resource_generation: object = None,
    ) -> None:
        if (
            type(plan_ref) is not str
            or _PLAN_REF.fullmatch(plan_ref) is None
            or type(plan_digest) is not str
            or _DIGEST.fullmatch(plan_digest) is None
            or (
                resource_generation is not None
                and not self._integer(resource_generation)
            )
        ):
            _fail("host.arguments_invalid")
        with self._state.locked():
            document = self._read_locked()
            saved = document["plans"].get(plan_ref)
            if saved is None or saved["state"] != "ready":
                _no_effect("provider.plan_missing")
            if saved["queue_plan_digest"] not in {None, plan_digest}:
                _no_effect("provider.plan_precondition_stale")
            if saved["queue_resource_generation"] not in {
                None,
                resource_generation,
            }:
                _no_effect("provider.resource_generation_stale")
            saved["queue_plan_digest"] = plan_digest
            saved["queue_resource_generation"] = resource_generation
            self._write_locked(document)

    def validate_plan_precondition(
        self,
        plan_ref: str,
        plan_digest: object,
        resource_generation: object = None,
    ) -> None:
        if (
            type(plan_ref) is not str
            or _PLAN_REF.fullmatch(plan_ref) is None
            or type(plan_digest) is not str
            or _DIGEST.fullmatch(plan_digest) is None
            or (
                resource_generation is not None
                and not self._integer(resource_generation)
            )
        ):
            _fail("host.arguments_invalid")
        with self._state.locked():
            saved = self._read_locked()["plans"].get(plan_ref)
        if saved is None:
            _no_effect("provider.plan_missing")
        if saved["queue_plan_digest"] != plan_digest:
            _no_effect("provider.plan_precondition_stale")
        if saved["queue_resource_generation"] != resource_generation:
            _no_effect("provider.resource_generation_stale")

    def validate_running_precondition(
        self,
        instance_ref: str,
        generation: object,
        plan_digest: object,
        resource_generation: object = None,
    ) -> None:
        if (
            type(instance_ref) is not str
            or _TOKEN.fullmatch(instance_ref) is None
            or not self._integer(generation)
            or type(plan_digest) is not str
            or _DIGEST.fullmatch(plan_digest) is None
            or (
                resource_generation is not None
                and not self._integer(resource_generation)
            )
        ):
            _fail("host.arguments_invalid")
        with self._state.locked():
            saved = self._read_locked()["running"].get(instance_ref)
        if saved is None:
            _no_effect("provider.instance_missing")
        if generation < saved["generation"]:
            _no_effect("provider.generation_stale")
        if saved["queue_plan_digest"] != plan_digest:
            _no_effect("provider.plan_precondition_stale")
        if saved["queue_resource_generation"] != resource_generation:
            _no_effect("provider.resource_generation_stale")

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
        with self._state.locked():
            document = self._read_locked()
            saved = document["running"].get(instance_ref)
            if saved is None:
                _no_effect("provider.instance_missing")
            if generation < saved["generation"]:
                _no_effect("provider.generation_stale")
            if (
                saved["state"] == "stopping"
                and self._claim_alive(saved["claim"])
                and not self._claim_owned(saved["claim"])
            ):
                _no_effect("provider.instance_stopping")
            saved["state"] = "stopping"
            saved["claim"] = self._claim()
            self._write_locked(document)
        try:
            running = self._running_instance(instance_ref, generation, allow_stopping=True)
        except OllamaRuntimeError as error:
            if str(error) != "provider.instance_absent":
                self._reset_stopping(instance_ref, saved)
                raise
            with self._state.locked():
                document = self._read_locked()
                if document["running"].get(instance_ref) == saved:
                    del document["running"][instance_ref]
                    self._write_locked(document)
            return {"stopped": True}
        except AgentOllamaError:
            self._reset_stopping(instance_ref, saved)
            raise
        # Any error from this effect boundary is ambiguous: preserve the durable
        # stopping claim so restart reconciliation can prove exact absence.
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

    def _reset_stopping(
        self, instance_ref: str, saved: Mapping[str, object]
    ) -> None:
        with self._state.locked():
            document = self._read_locked()
            current = document["running"].get(instance_ref)
            if (
                current is not None
                and current["state"] == "stopping"
                and current["claim"] == saved["claim"]
                and current["unit_name"] == saved["unit_name"]
                and current["ollama_pid"] == saved["ollama_pid"]
                and current["process_start_ticks"]
                == saved["process_start_ticks"]
            ):
                current.update(state="running", claim=None)
                self._write_locked(document)

    def _fresh_plan(
        self, instance_ref: str, generation: int
    ) -> tuple[OllamaRegistryV1, OllamaLocalPlan]:
        registry = self._load_generation(generation)
        instance = self._local_instance(registry, instance_ref)
        return registry, plan_local_instance(
            instance, probe_ollama_host(runtime=self._runtime), registry=registry
        )

    def _running_instance(
        self, instance_ref: str, generation: int, *, allow_stopping: bool = False
    ) -> RunningOllamaInstance:
        with self._state.locked():
            saved = self._read_locked()["running"].get(instance_ref)
        if saved is None:
            _no_effect("provider.instance_missing")
        if generation < saved["generation"]:
            _no_effect("provider.generation_stale")
        if (
            saved["state"] == "stopping"
            and not allow_stopping
            and self._claim_alive(saved["claim"])
        ):
            _no_effect("provider.instance_stopping")
        _registry, plan = self._fresh_plan_current(instance_ref)
        if ollama_plan_digest(plan) != saved["plan_digest"]:
            _no_effect("provider.plan_changed")
        running = adopt_running_instance(plan, runtime=self._runtime, **{
            key: saved[key]
            for key in (
                "unit_name", "port", "ollama_pid", "control_group",
                "process_start_ticks",
            )
        })
        if saved["generation"] != generation:
            with self._state.locked():
                document = self._read_locked()
                if document["running"].get(instance_ref) == saved:
                    document["running"][instance_ref]["generation"] = generation
                    self._write_locked(document)
        return running

    def _reap_dead_running(self, instance_ref: str) -> None:
        with self._state.locked():
            saved = self._read_locked()["running"].get(instance_ref)
        if saved is None:
            return
        if saved["state"] != "running":
            return
        try:
            _registry, plan = self._fresh_plan_current(instance_ref)
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
            if str(error) != "provider.instance_absent":
                return
        with self._state.locked():
            document = self._read_locked()
            if document["running"].get(instance_ref) == saved:
                del document["running"][instance_ref]
                self._write_locked(document)

    def _fresh_plan_current(
        self, instance_ref: str
    ) -> tuple[OllamaRegistryV1, OllamaLocalPlan]:
        registry = self._registry.load()
        instance = self._local_instance(registry, instance_ref)
        return registry, plan_local_instance(
            instance, probe_ollama_host(runtime=self._runtime), registry=registry
        )

    def _reap_absent_intents(self, *, skip_ref: str | None = None) -> None:
        with self._state.locked():
            plans = dict(self._read_locked()["plans"])
        for plan_ref in sorted(plans):
            if plan_ref == skip_ref:
                continue
            saved = plans[plan_ref]
            if (
                saved["state"] != "intent"
                or self._claim_alive(saved["claim"])
            ):
                continue
            try:
                _registry, plan = self._fresh_plan_current(saved["instance_ref"])
                if ollama_plan_digest(plan) != saved["plan_digest"]:
                    continue
                running = recover_started_instance(
                    plan,
                    unit_name=saved["unit_name"],
                    port=saved["port"],
                    runtime=self._runtime,
                )
            except (AgentOllamaError, OllamaRuntimeError):
                continue
            if running is not None:
                try:
                    self._commit_running(plan_ref, saved, running)
                except AgentOllamaError:
                    pass
                continue
            with self._state.locked():
                document = self._read_locked()
                if document["plans"].get(plan_ref) == saved:
                    del document["plans"][plan_ref]
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
                return {"schema_version": 2, "plans": {}, "running": {}}
            _fail("provider.journal_unavailable")
        try:
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
        except (UnicodeError, ValueError, TypeError, RecursionError):
            _fail("provider.journal_unavailable")
        if type(value) is dict and value.get("schema_version") == 1:
            if (
                set(value) != {"schema_version", "plans", "running"}
                or type(value.get("plans")) is not dict
                or type(value.get("running")) is not dict
            ):
                _fail("provider.journal_unavailable")
            for item in value["plans"].values():
                if type(item) is not dict:
                    _fail("provider.journal_unavailable")
                if "unit_name" not in item and "port" not in item:
                    old_state = item.get("state")
                    if old_state != "ready":
                        # Schema 1 had no stable unit identity.  A dead owner may
                        # already have started a scope, so deletion is unsafe.
                        _fail("provider.journal_unavailable")
                    item["state"] = "ready"
                    item["unit_name"] = None
                    item["port"] = None
            for item in value["running"].values():
                if type(item) is not dict:
                    _fail("provider.journal_unavailable")
                item.setdefault("state", "running")
                item.setdefault("claim", None)
            value["schema_version"] = 2
        if (
            type(value) is not dict
            or set(value) != {"schema_version", "plans", "running"}
            or value["schema_version"] != 2
            or type(value["plans"]) is not dict
            or type(value["running"]) is not dict
            or len(value["plans"]) > self._max_plans
            or len(value["running"]) > 64
        ):
            _fail("provider.journal_unavailable")
        for item in value["plans"].values():
            if type(item) is not dict:
                _fail("provider.journal_unavailable")
            item.setdefault("queue_plan_digest", None)
            item.setdefault("queue_resource_generation", None)
        for item in value["running"].values():
            if type(item) is not dict:
                _fail("provider.journal_unavailable")
            item.setdefault("queue_plan_digest", None)
            item.setdefault("queue_resource_generation", None)
        for ref, item in value["plans"].items():
            if (
                type(ref) is not str or _PLAN_REF.fullmatch(ref) is None
                or type(item) is not dict
                or set(item)
                != {
                    "instance_ref",
                    "generation",
                    "plan_digest",
                    "created_at",
                    "state",
                    "claim",
                    "unit_name",
                    "port",
                    "queue_plan_digest",
                    "queue_resource_generation",
                }
                or type(item["instance_ref"]) is not str
                or _TOKEN.fullmatch(item["instance_ref"]) is None
                or not self._integer(item["generation"])
                or type(item["plan_digest"]) is not str
                or _DIGEST.fullmatch(item["plan_digest"]) is None
                or (
                    item["queue_plan_digest"] is not None
                    and (
                        type(item["queue_plan_digest"]) is not str
                        or _DIGEST.fullmatch(item["queue_plan_digest"]) is None
                    )
                )
                or (
                    item["queue_resource_generation"] is not None
                    and not self._integer(item["queue_resource_generation"])
                )
                or not self._integer(item["created_at"])
                or item["state"] not in {"ready", "intent"}
                or not self._valid_claim(
                    item["claim"], required=item["state"] == "intent"
                )
                or (
                    item["state"] == "ready"
                    and (item["unit_name"] is not None or item["port"] is not None)
                )
                or (
                    item["state"] == "intent"
                    and (
                        type(item["unit_name"]) is not str
                        or _UNIT.fullmatch(item["unit_name"]) is None
                        or not self._integer(item["port"], 1, 65535)
                    )
                )
            ):
                _fail("provider.journal_unavailable")
        for ref, item in value["running"].items():
            if (
                type(ref) is not str or _TOKEN.fullmatch(ref) is None
                or type(item) is not dict
                or set(item)
                != {
                    "generation",
                    "plan_digest",
                    "unit_name",
                    "port",
                    "ollama_pid",
                    "control_group",
                    "process_start_ticks",
                    "state",
                    "claim",
                    "queue_plan_digest",
                    "queue_resource_generation",
                }
                or not self._integer(item["generation"])
                or type(item["plan_digest"]) is not str
                or _DIGEST.fullmatch(item["plan_digest"]) is None
                or (
                    item["queue_plan_digest"] is not None
                    and (
                        type(item["queue_plan_digest"]) is not str
                        or _DIGEST.fullmatch(item["queue_plan_digest"]) is None
                    )
                )
                or (
                    item["queue_resource_generation"] is not None
                    and not self._integer(item["queue_resource_generation"])
                )
                or type(item["unit_name"]) is not str
                or _UNIT.fullmatch(item["unit_name"]) is None
                or not self._integer(item["port"], 1, 65535)
                or not self._integer(item["ollama_pid"], 1)
                or type(item["control_group"]) is not str
                or not item["control_group"].startswith("/")
                or "\n" in item["control_group"]
                or not self._integer(item["process_start_ticks"], 1)
                or item["state"] not in {"running", "stopping"}
                or not self._valid_claim(
                    item["claim"], required=item["state"] == "stopping"
                )
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

    def _claim_owned(self, value: object) -> bool:
        if not self._valid_claim(value, required=True):
            return False
        claim = cast(dict[str, object], value)
        return (
            claim["boot_id"] == self._boot_id()
            and claim["pid"] == os.getpid()
            and claim["process_start_ticks"] == self._process_start_ticks(os.getpid())
            and claim["thread_id"] == threading.get_native_id()
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

    def plan(
        self,
        value: object,
        *,
        plan_precondition_digest: str | None = None,
        resource_generation: int | None = None,
    ) -> dict[str, object]:
        result = dict(self._operations.plan(self.validate("plan", value)))
        if plan_precondition_digest is not None or resource_generation is not None:
            plan_ref = result.get("plan_ref")
            bind = getattr(self._operations, "bind_plan_precondition", None)
            if (
                type(plan_ref) is not str
                or plan_precondition_digest is None
                or not callable(bind)
            ):
                _fail("provider.plan_precondition_stale")
            bind(plan_ref, plan_precondition_digest, resource_generation)
        return result

    def apply(
        self,
        value: object,
        *,
        plan_precondition_digest: str | None = None,
        resource_generation: int | None = None,
    ) -> dict[str, object]:
        arguments = self.validate("apply", value)
        if plan_precondition_digest is not None or resource_generation is not None:
            validate = getattr(self._operations, "validate_plan_precondition", None)
            if plan_precondition_digest is None or not callable(validate):
                _fail("provider.plan_precondition_stale")
            validate(
                arguments["plan_ref"], plan_precondition_digest, resource_generation
            )
        return dict(self._operations.apply(arguments))

    def probe(
        self,
        value: object,
        *,
        plan_precondition_digest: str | None = None,
        resource_generation: int | None = None,
    ) -> dict[str, object]:
        arguments = self.validate("probe", value)
        self._validate_running_precondition(
            arguments, plan_precondition_digest, resource_generation
        )
        return dict(self._operations.probe(arguments))

    def stop(
        self,
        value: object,
        *,
        plan_precondition_digest: str | None = None,
        resource_generation: int | None = None,
    ) -> dict[str, object]:
        arguments = self.validate("stop", value)
        self._validate_running_precondition(
            arguments, plan_precondition_digest, resource_generation
        )
        return dict(self._operations.stop(arguments))

    def _validate_running_precondition(
        self,
        arguments: Mapping[str, object],
        plan_precondition_digest: str | None,
        resource_generation: int | None,
    ) -> None:
        if plan_precondition_digest is None and resource_generation is None:
            return
        validate = getattr(self._operations, "validate_running_precondition", None)
        if plan_precondition_digest is None or not callable(validate):
            _fail("provider.plan_precondition_stale")
        validate(
            arguments["instance_ref"],
            arguments["generation"],
            plan_precondition_digest,
            resource_generation,
        )


__all__ = [
    "AgentOllamaError", "AgentOllamaExecutor", "AgentOllamaNoEffectError",
    "AgentOllamaOperations", "MAX_AGENT_OLLAMA_PLANS",
    "ProductionAgentOllamaAdapter",
]
