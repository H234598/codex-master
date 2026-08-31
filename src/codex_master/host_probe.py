"""Bounded, privacy-preserving active host probe evidence."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import platform
from typing import Protocol, cast

from .admin_contracts import OperationV1
from .agent_contracts import AgentReceiptV1
from .agent_operations import AgentOperationError, AgentOperationRequestV1, AgentOperationStore
from .admin_operations import AdminOperationStore
from .admin_hosts import HostRegistry


class HostProbeError(ValueError):
    """Stable error with no host-local diagnostic details."""

    def __init__(self, code: str = "host.probe_failed") -> None:
        super().__init__(code)


class HostProbeKernel(Protocol):
    cpu_count: object
    memory_bytes: object

    def uname(self) -> tuple[str, str]: ...
    def cgroup_v2(self) -> bool: ...
    def systemd(self) -> bool: ...
    def load(self) -> float: ...
    def pressure(self) -> float: ...
    def ollama_available(self) -> bool: ...


class HostProbePort(Protocol):
    def probe(
        self, host_ref: str, *, expected_generation: int, idempotency_key: str
    ) -> OperationV1: ...


def _utc_timestamp(value: datetime) -> str:
    if type(value) is not datetime or value.tzinfo is None or value.microsecond:
        raise HostProbeError()
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _integer(value: object, *, maximum: int = 2**31 - 1) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise HostProbeError()
    return cast(int, value)


def _classify_memory(value: object) -> str:
    memory = _integer(value, maximum=2**63 - 1)
    gib = memory // 1024**3
    if gib < 8:
        return "under-8-gib"
    if gib < 32:
        return "8-31-gib"
    if gib < 128:
        return "32-127-gib"
    return "128-plus-gib"


def _classify_load(value: object, cpu_count: int) -> str:
    if type(value) not in {int, float} or type(value) is bool or value < 0:
        raise HostProbeError()
    ratio = float(value) / cpu_count
    return "idle" if ratio < 0.5 else "busy" if ratio < 1.0 else "saturated"


def _classify_pressure(value: object) -> str:
    if type(value) not in {int, float} or type(value) is bool or not 0 <= value <= 100:
        raise HostProbeError()
    return "none" if value == 0 else "low" if value < 10 else "elevated"


@dataclass(frozen=True, slots=True)
class HostProbeEvidenceV1:
    kernel_class: str
    architecture_class: str
    cpu_count: int
    memory_class: str
    cgroup_v2: bool
    systemd: bool
    load_class: str
    pressure_class: str
    ollama_capability: bool
    observed_at: str
    agent_generation: int = 1

    def __post_init__(self) -> None:
        if self.kernel_class not in {"linux", "other"} or self.architecture_class not in {"x86_64", "arm64", "other"}:
            raise HostProbeError()
        _integer(self.cpu_count)
        if self.memory_class not in {"under-8-gib", "8-31-gib", "32-127-gib", "128-plus-gib"}:
            raise HostProbeError()
        if type(self.cgroup_v2) is not bool or type(self.systemd) is not bool or type(self.ollama_capability) is not bool:
            raise HostProbeError()
        if self.load_class not in {"idle", "busy", "saturated"} or self.pressure_class not in {"none", "low", "elevated"}:
            raise HostProbeError()
        if type(self.observed_at) is not str:
            raise HostProbeError()
        try:
            observed = datetime.strptime(self.observed_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
        except ValueError:
            raise HostProbeError() from None
        if observed.strftime("%Y-%m-%dT%H:%M:%SZ") != self.observed_at:
            raise HostProbeError()
        _integer(self.agent_generation)

    def public(self) -> dict[str, object]:
        value = {
            "kernel_class": self.kernel_class, "architecture_class": self.architecture_class,
            "cpu_count": self.cpu_count, "memory_class": self.memory_class,
            "cgroup_v2": self.cgroup_v2, "systemd": self.systemd,
            "load_class": self.load_class, "pressure_class": self.pressure_class,
            "ollama_capability": self.ollama_capability, "observed_at": self.observed_at,
            "agent_generation": self.agent_generation,
        }
        canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        return {**value, "evidence_digest": "sha256:" + hashlib.sha256(canonical).hexdigest()}

    @classmethod
    def from_public(cls, value: object) -> "HostProbeEvidenceV1":
        if type(value) is not dict or set(value) != {
            "kernel_class", "architecture_class", "cpu_count", "memory_class",
            "cgroup_v2", "systemd", "load_class", "pressure_class",
            "ollama_capability", "observed_at", "agent_generation", "evidence_digest",
        }:
            raise HostProbeError()
        evidence = cls(
            value["kernel_class"], value["architecture_class"], value["cpu_count"], value["memory_class"],
            value["cgroup_v2"], value["systemd"], value["load_class"], value["pressure_class"],
            value["ollama_capability"], value["observed_at"], value["agent_generation"],
        )
        if evidence.public()["evidence_digest"] != value["evidence_digest"]:
            raise HostProbeError()
        return evidence


class LocalHostProbeCollector:
    def __init__(self, clock: Callable[[], datetime] | None = None) -> None:
        self._clock = clock or (lambda: datetime.now(UTC).replace(microsecond=0))

    def collect(self, kernel: HostProbeKernel | None = None) -> HostProbeEvidenceV1:
        try:
            source = kernel or _SystemKernel()
            system, machine = source.uname()
            cpu_count = _integer(source.cpu_count)
            return HostProbeEvidenceV1(
                "linux" if system.lower() == "linux" else "other",
                "x86_64" if machine.lower() in {"x86_64", "amd64"} else "arm64" if machine.lower() in {"aarch64", "arm64"} else "other",
                cpu_count, _classify_memory(source.memory_bytes), source.cgroup_v2(),
                source.systemd(), _classify_load(source.load(), cpu_count),
                _classify_pressure(source.pressure()), source.ollama_available(),
                _utc_timestamp(self._clock()),
            )
        except HostProbeError:
            raise
        except (OSError, RuntimeError, ValueError, TypeError):
            raise HostProbeError() from None


class _SystemKernel:
    @property
    def cpu_count(self) -> object:
        return os.cpu_count()

    @property
    def memory_bytes(self) -> object:
        for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) * 1024
        raise OSError

    def uname(self) -> tuple[str, str]:
        return platform.system(), platform.machine()

    def cgroup_v2(self) -> bool:
        return Path("/sys/fs/cgroup/cgroup.controllers").is_file()

    def systemd(self) -> bool:
        return Path("/run/systemd/system").is_dir()

    def load(self) -> float:
        return os.getloadavg()[0]

    def pressure(self) -> float:
        line = Path("/proc/pressure/cpu").read_text(encoding="ascii").splitlines()[0]
        return float(next(item[4:] for item in line.split() if item.startswith("avg10=")))

    def ollama_available(self) -> bool:
        return Path("/run/ollama/ollama.sock").is_socket()


class LocalHostProbeAdapter:
    """Collect one bounded local observation and finish its admin operation."""

    def __init__(
        self,
        *,
        operation_store: AdminOperationStore,
        host_registry: HostRegistry,
        collector: LocalHostProbeCollector | None = None,
    ) -> None:
        self._operations = operation_store
        self._registry = host_registry
        self._collector = collector or LocalHostProbeCollector()

    def probe(
        self, host_ref: str, *, expected_generation: int, idempotency_key: str
    ) -> OperationV1:
        plan = self._operations.plan(
            kind="hosts.probe", generation=expected_generation,
            key=_operation_key(host_ref, idempotency_key), steps=("host.probe.collect",),
        )
        if plan.operation.state != "planned":
            return plan.operation
        self._operations.begin(plan.operation.id, current_generation=expected_generation)
        try:
            evidence = self._collector.collect()
            self._registry.record_active_probe(
                host_ref,
                generation=expected_generation,
                resource_evidence={
                    "cpu_threads": evidence.cpu_count,
                    "memory_bytes": _memory_floor(evidence.memory_class),
                },
                observed_at=evidence.observed_at,
            )
        except Exception:
            self._operations.record_step(
                plan.operation.id, "host.probe.collect", succeeded=False,
                reason_code="host.probe_failed",
            )
            return self._operations.finish(
                plan.operation.id, state="failed", reason_codes=("host.probe_failed",),
            )
        self._operations.record_step(plan.operation.id, "host.probe.collect", succeeded=True)
        return self._operations.finish(
            plan.operation.id, state="succeeded", resulting_generation=expected_generation,
        )


class RemoteHostProbeAdapter:
    """Queue only the fixed host-agent collection action; never run a shell."""

    def __init__(
        self,
        *,
        operation_store: AdminOperationStore,
        agent_operations: AgentOperationStore,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._operations = operation_store
        self._agent_operations = agent_operations
        self._clock = clock or (lambda: datetime.now(UTC).replace(microsecond=0))

    def probe(
        self, host_ref: str, *, expected_generation: int, idempotency_key: str
    ) -> OperationV1:
        plan = self._operations.plan(
            kind="hosts.probe", generation=expected_generation,
            key=_operation_key(host_ref, idempotency_key), steps=("host.probe.collect",),
        )
        if plan.operation.state != "planned":
            return plan.operation
        self._agent_operations.enqueue(
            AgentOperationRequestV1(
                key=_operation_key(host_ref, idempotency_key), kind="host.probe", action="collect",
                registry_generation=expected_generation,
                plan_digest=plan.plan_digest,
                arguments={"admin_operation_id": plan.operation_id, "probe_schema": 1},
                deadline=(self._clock().astimezone(UTC).replace(microsecond=0) + timedelta(minutes=5)),
                target_host_ref=host_ref,
            )
        )
        return plan.operation


class RemoteHostProbeCompletionOwner:
    """Task-6-only receipt completion boundary for fixed probe results."""

    def __init__(
        self,
        *,
        operation_store: AdminOperationStore,
        agent_operations: AgentOperationStore,
        host_registry: HostRegistry,
    ) -> None:
        self._operations = operation_store
        self._agent_operations = agent_operations
        self._registry = host_registry

    def complete(self, principal: object, receipt: AgentReceiptV1) -> object:
        context = self._agent_operations.context(receipt.operation_id)
        if receipt.result.kind != "host.probe" or receipt.result.action != "collect":
            return self._agent_operations.complete(principal, receipt)  # type: ignore[arg-type]
        target = context["target_host_ref"]
        arguments = context["arguments"]
        if type(target) is not str or not isinstance(arguments, Mapping):
            raise HostProbeError()
        if getattr(principal, "host_ref", None) != target:
            raise AgentOperationError("host.identity_mismatch")
        operation_id = arguments.get("admin_operation_id")
        generation = context["registry_generation"]
        if type(operation_id) is not str or type(generation) is not int:
            raise HostProbeError()
        if receipt.state != "succeeded":
            self._agent_operations.complete(principal, receipt)  # type: ignore[arg-type]
            return self._fail(operation_id, generation, "host.probe_unknown")
        try:
            evidence = HostProbeEvidenceV1.from_public(dict(receipt.result.payload))
            host = next(item for item in self._registry.list() if item.ref == target)
            if host.generation != generation or getattr(principal, "registry_generation", None) != generation:
                raise HostProbeError()
            operation = self._operations.get(operation_id)
            if operation.state in {"succeeded", "failed", "partial", "blocked"}:
                return self._agent_operations.complete(principal, receipt)  # type: ignore[arg-type]
            self._operations.begin(operation_id, current_generation=generation)
            self._registry.record_active_probe(
                target,
                generation=generation,
                resource_evidence={
                    "cpu_threads": evidence.cpu_count,
                    "memory_bytes": _memory_floor(evidence.memory_class),
                },
                observed_at=evidence.observed_at,
            )
            self._operations.record_step(operation_id, "host.probe.collect", succeeded=True)
            self._operations.finish(operation_id, state="succeeded", resulting_generation=generation)
            return self._agent_operations.complete(principal, receipt)  # type: ignore[arg-type]
        except (HostProbeError, StopIteration, ValueError):
            self._agent_operations.complete(principal, receipt)  # type: ignore[arg-type]
            return self._fail(operation_id, generation, "host.probe_failed")

    def _fail(self, operation_id: str, generation: int, reason: str) -> object:
        try:
            self._operations.begin(operation_id, current_generation=generation)
            self._operations.record_step(operation_id, "host.probe.collect", succeeded=False, reason_code=reason)
            return self._operations.finish(operation_id, state="failed", reason_codes=(reason,))
        except Exception:
            return self._operations.get(operation_id)


class HostProbeRouter:
    """Choose the directly-attached control host without exposing transport data."""

    def __init__(
        self, *, local_host_ref: str, local: HostProbePort, remote: HostProbePort
    ) -> None:
        self._local_host_ref = local_host_ref
        self._local = local
        self._remote = remote

    def probe(
        self, host_ref: str, *, expected_generation: int, idempotency_key: str
    ) -> OperationV1:
        owner = self._local if host_ref == self._local_host_ref else self._remote
        return owner.probe(
            host_ref,
            expected_generation=expected_generation,
            idempotency_key=idempotency_key,
        )


def _memory_floor(memory_class: str) -> int:
    return {
        "under-8-gib": 1 * 1024**3, "8-31-gib": 8 * 1024**3,
        "32-127-gib": 32 * 1024**3, "128-plus-gib": 128 * 1024**3,
    }[memory_class]


def _operation_key(host_ref: str, idempotency_key: str) -> str:
    if type(host_ref) is not str or type(idempotency_key) is not str:
        raise HostProbeError()
    return "probe-" + hashlib.sha256(f"{host_ref}\0{idempotency_key}".encode("ascii")).hexdigest()
