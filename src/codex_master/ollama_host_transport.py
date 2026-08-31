"""Typed, fenced Ollama placement over local or registered host adapters."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
import hashlib
import json
import math
import secrets
import threading
import time
from typing import Callable, Mapping, NoReturn, Protocol
import weakref

from codex_master.admin_contracts import OperationV1
from codex_master.agent_operations import AgentOperationRequestV1, AgentOperationStore
from codex_master.admin_hosts import HostRegistry, HostRegistryError
from codex_master.ollama_registry import (
    OllamaInstanceV1,
    OllamaRegistryV1,
)
from codex_master.ollama_runtime import (
    OllamaReadinessStatus,
    OllamaRuntime,
    OllamaRuntimeError,
    plan_local_instance,
    probe_instance_readiness,
    probe_ollama_host,
    start_local_instance,
    stop_local_instance,
)


CONTROL_HOST_REF = "control-host"
OLLAMA_OPERATION_TYPE = "ollama.instance"
_PLAN_SEAL = object()
_EXECUTION_SEAL = object()
_RECORD_LOCK = threading.RLock()
_PLAN_RECORDS: dict[bytes, tuple[weakref.ReferenceType[object], tuple[object, ...]]] = {}
_EXECUTION_RECORDS: dict[
    bytes, tuple[weakref.ReferenceType[object], tuple[object, ...]]
] = {}


class OllamaHostError(RuntimeError):
    """Code-only host-placement failure."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _fail(code: str) -> NoReturn:
    raise OllamaHostError(code) from None


def _safe_token(value: object, *, maximum: int = 128) -> bool:
    return (
        type(value) is str
        and 0 < len(value) <= maximum
        and all(
            character.isascii()
            and (character.isalnum() or character in "._-")
            for character in value
        )
    )


def _digest(value: dict[str, object]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _owner_instance_document(instance: OllamaInstanceV1) -> dict[str, object]:
    """Master-private, bounded recovery metadata; never serialized to an agent."""
    return {
        "ref": instance.ref,
        "label": instance.label,
        "host_ref": instance.host_ref,
        "ollama_executable": instance.ollama_executable,
        "models_directory": instance.models_directory,
        "selected_model_refs": list(instance.selected_model_refs),
        "allowed_cpus": instance.allowed_cpus,
        "cpu_quota_percent": instance.cpu_quota_percent,
        "cpu_weight": instance.cpu_weight,
        "lifecycle_state": instance.lifecycle_state,
        "readiness_state": instance.readiness_state,
    }


@dataclass(frozen=True, slots=True)
class OllamaHostLease:
    host_ref: str
    lease_id: str = field(repr=False)
    runtime_generation: int
    fence: int
    expires_at_monotonic: float

    def __post_init__(self) -> None:
        if (
            not _safe_token(self.host_ref)
            or not _safe_token(self.lease_id)
            or type(self.runtime_generation) is not int
            or self.runtime_generation < 0
            or type(self.fence) is not int
            or self.fence < 0
            or type(self.expires_at_monotonic) not in (int, float)
            or not math.isfinite(float(self.expires_at_monotonic))
            or self.expires_at_monotonic <= 0
        ):
            _fail("resource.host_lease_invalid")


@dataclass(frozen=True, slots=True, weakref_slot=True)
class OllamaHostPlan:
    schema_version: int
    host_ref: str
    instance_ref: str
    model_generation: int
    runtime_generation: int
    fence: int
    plan_digest: str
    idempotency_key: str
    expires_at_monotonic: float
    lease_id: str = field(repr=False)
    _registry: OllamaRegistryV1 = field(repr=False, compare=False)
    _instance: OllamaInstanceV1 = field(repr=False, compare=False)
    _local_plan: object | None = field(repr=False, compare=False)
    _provenance: bytes = field(repr=False, compare=False)
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (
            self._seal is not _PLAN_SEAL
            or self.schema_version != 1
            or not _safe_token(self.host_ref)
            or not _safe_token(self.instance_ref)
            or type(self.model_generation) is not int
            or self.model_generation < 0
            or type(self.runtime_generation) is not int
            or self.runtime_generation < 0
            or type(self.fence) is not int
            or self.fence < 0
            or not _hex_token(self.plan_digest, 64)
            or not _hex_token(self.idempotency_key, 64)
            or not _safe_token(self.lease_id)
            or not isinstance(self._registry, OllamaRegistryV1)
            or not isinstance(self._instance, OllamaInstanceV1)
            or self._instance.ref != self.instance_ref
            or type(self.expires_at_monotonic) not in (int, float)
            or not math.isfinite(float(self.expires_at_monotonic))
            or not isinstance(self._provenance, bytes)
            or len(self._provenance) != 32
        ):
            _fail("provider.plan_invalid")


@dataclass(frozen=True, slots=True, weakref_slot=True)
class OllamaHostExecution:
    plan: OllamaHostPlan
    _runtime_value: object | None = field(repr=False, compare=False)
    _provenance: bytes = field(repr=False, compare=False)
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (
            self._seal is not _EXECUTION_SEAL
            or not isinstance(self.plan, OllamaHostPlan)
            or not isinstance(self._provenance, bytes)
            or len(self._provenance) != 32
        ):
            _fail("provider.instance_invalid")


class OllamaRegistrySource(Protocol):
    def load(self) -> OllamaRegistryV1: ...


class OllamaHostLeaseSource(Protocol):
    def resolve(self, host_ref: str) -> OllamaHostLease | None: ...


class LocalOllamaHostAdapter(Protocol):
    def plan(
        self, instance: OllamaInstanceV1, registry: OllamaRegistryV1
    ) -> object: ...

    def apply(self, plan: object) -> object: ...

    def probe(self, running: object) -> OllamaReadinessStatus: ...

    def stop(self, running: object) -> None: ...


@dataclass(frozen=True, slots=True)
class OllamaRemotePlanRequestV1:
    """One bounded remote plan request, without host-local paths or argv."""

    host_ref: str
    instance_ref: str
    registry_generation: int
    runtime_generation: int
    fence: int
    lease_epoch: int
    plan_digest: str
    idempotency_key: str
    selected_model_refs: tuple[str, ...]
    allowed_cpus: str
    cpu_quota_percent: int
    cpu_weight: int
    resource_generation: int | None = None
    owner_instance: Mapping[str, object] | None = field(default=None, repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class OllamaRemoteApplyRequestV1:
    host_ref: str
    instance_ref: str
    registry_generation: int
    resource_generation: int | None
    lease_epoch: int
    plan_digest: str
    plan_ref: str
    plan_precondition_digest: str | None = None
    owner_plan_id: str | None = None
    owner_instance: Mapping[str, object] | None = field(default=None, repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class OllamaRemoteProbeRequestV1:
    host_ref: str
    instance_ref: str
    registry_generation: int
    resource_generation: int | None
    lease_epoch: int
    plan_digest: str
    plan_precondition_digest: str | None = None
    owner_plan_id: str | None = None
    owner_instance: Mapping[str, object] | None = field(default=None, repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class OllamaRemoteStopRequestV1:
    host_ref: str
    instance_ref: str
    registry_generation: int
    resource_generation: int | None
    lease_epoch: int
    plan_digest: str
    plan_precondition_digest: str | None = None
    owner_plan_id: str | None = None
    owner_instance: Mapping[str, object] | None = field(default=None, repr=False, compare=False)


class RemoteOllamaOperationPort(Protocol):
    """The sole remote boundary: every call creates a durable agent operation."""

    def plan(self, request: OllamaRemotePlanRequestV1) -> OperationV1: ...

    def apply(self, request: OllamaRemoteApplyRequestV1) -> OperationV1: ...

    def probe(self, request: OllamaRemoteProbeRequestV1) -> OperationV1: ...

    def stop(self, request: OllamaRemoteStopRequestV1) -> OperationV1: ...


class AgentQueueRemoteOllamaOperationPort:
    """Enqueue the four fixed Ollama actions in the canonical agent queue.

    The agent receives only the exact arguments accepted by ``AgentOllamaExecutor``.
    Host identity, the queue generation and the lease epoch remain master-side
    fences; the control host never reaches this object.
    """

    __slots__ = ("_agent_operations", "_hosts", "_clock")

    def __init__(
        self,
        *,
        agent_operations: AgentOperationStore,
        host_registry: HostRegistry,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(agent_operations, AgentOperationStore) or not isinstance(
            host_registry, HostRegistry
        ):
            _fail("resource.host_unreachable")
        self._agent_operations = agent_operations
        self._hosts = host_registry
        self._clock = clock or (lambda: datetime.now(UTC).replace(microsecond=0))

    def plan(self, request: OllamaRemotePlanRequestV1) -> OperationV1:
        arguments = {
            "instance_ref": request.instance_ref,
            "generation": request.registry_generation,
        }
        return self._enqueue("plan", request, arguments)

    def apply(self, request: OllamaRemoteApplyRequestV1) -> OperationV1:
        return self._enqueue("apply", request, {"plan_ref": request.plan_ref})

    def probe(self, request: OllamaRemoteProbeRequestV1) -> OperationV1:
        return self._enqueue(
            "probe",
            request,
            {"instance_ref": request.instance_ref, "generation": request.registry_generation},
        )

    def stop(self, request: OllamaRemoteStopRequestV1) -> OperationV1:
        return self._enqueue(
            "stop",
            request,
            {"instance_ref": request.instance_ref, "generation": request.registry_generation},
        )

    def _enqueue(
        self,
        action: str,
        request: (
            OllamaRemotePlanRequestV1
            | OllamaRemoteApplyRequestV1
            | OllamaRemoteProbeRequestV1
            | OllamaRemoteStopRequestV1
        ),
        arguments: dict[str, object],
    ) -> OperationV1:
        _validate_remote_request(action, request)
        try:
            binding = self._hosts.agent_binding(request.host_ref)
            generation = self._hosts.document_generation()
        except HostRegistryError as error:
            raise OllamaHostError(error.code) from None
        if not binding.enabled or binding.lease_epoch != request.lease_epoch:
            _fail("control.plan_stale")
        key_material = json.dumps(
            {
                "action": action,
                "arguments": arguments,
                "host_ref": request.host_ref,
                "lease_epoch": request.lease_epoch,
                "plan_digest": request.plan_digest,
                "resource_generation": _request_resource_generation(request),
                "plan_precondition_digest": _request_plan_precondition_digest(request),
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        try:
            now = self._clock()
            if type(now) is not datetime or now.tzinfo is None:
                _fail("resource.host_unreachable")
            queued = self._agent_operations.enqueue(
                AgentOperationRequestV1(
                    key="ollama-" + hashlib.sha256(key_material).hexdigest(),
                    kind=OLLAMA_OPERATION_TYPE,
                    action=action,  # type: ignore[arg-type]
                    registry_generation=generation,
                    plan_digest="sha256:" + request.plan_digest,
                    arguments=arguments,
                    deadline=now.astimezone(UTC).replace(microsecond=0)
                    + timedelta(minutes=5),
                    target_host_ref=request.host_ref,
                    required_registry_generation=generation,
                    required_lease_epoch=request.lease_epoch,
                    resource_generation=_request_resource_generation(request),
                    plan_precondition_digest="sha256:"
                    + _request_plan_precondition_digest(request),
                    # This bounded master-private envelope is committed in the
                    # queue transaction.  It lets a fresh FleetService recover
                    # the typed owner after a crash between enqueue and index.
                    owner_context={
                        "schema_version": 1,
                        "owner": "ollama.remote",
                        "action": action,
                        "host_ref": request.host_ref,
                        "instance_ref": request.instance_ref,
                        "registry_generation": generation,
                        "ollama_registry_generation": request.registry_generation,
                        "resource_generation": _request_resource_generation(request),
                        "lease_epoch": request.lease_epoch,
                        "queue_plan_digest": "sha256:" + request.plan_digest,
                        "plan_precondition_digest": "sha256:"
                        + _request_plan_precondition_digest(request),
                        "instance": request.owner_instance,
                        **(
                            {"plan_id": request.owner_plan_id}
                            if not isinstance(request, OllamaRemotePlanRequestV1)
                            else {}
                        ),
                    },
                )
            )
        except OllamaHostError:
            raise
        except Exception:
            _fail("resource.host_unreachable")
        return _operation_from_agent_view(queued)


class HostRegistryOllamaLeaseSource:
    """Derive one short-lived remote fence from the registered agent epoch."""

    __slots__ = ("_hosts", "_monotonic", "_local")

    def __init__(
        self, hosts: HostRegistry, *, monotonic: Callable[[], float] = time.monotonic
    ) -> None:
        self._hosts = hosts
        self._monotonic = monotonic
        self._local = OllamaHostLease(
            CONTROL_HOST_REF,
            "control-daemon",
            1,
            1,
            monotonic() + 365 * 24 * 60 * 60,
        )

    def resolve(self, host_ref: str) -> OllamaHostLease | None:
        if host_ref == CONTROL_HOST_REF:
            return self._local
        try:
            binding = self._hosts.agent_binding(host_ref)
        except HostRegistryError:
            return None
        if not binding.enabled:
            return None
        return OllamaHostLease(
            host_ref,
            "agent-" + str(binding.lease_epoch),
            1,
            binding.lease_epoch,
            self._monotonic() + 15 * 60,
        )


class Task3LocalOllamaHostAdapter:
    """Thin control-host adapter over Task 3's hardened local runtime."""

    __slots__ = ("_runtime",)

    def __init__(self, runtime: OllamaRuntime | None = None) -> None:
        self._runtime = runtime

    def plan(
        self, instance: OllamaInstanceV1, registry: OllamaRegistryV1
    ) -> object:
        local_instance = replace(instance, host_ref="local")
        local_registry = _registry_with_instance(registry, local_instance)
        host = probe_ollama_host(runtime=self._runtime)
        return plan_local_instance(local_instance, host, registry=local_registry)

    def apply(self, plan: object) -> object:
        return start_local_instance(plan, runtime=self._runtime)  # type: ignore[arg-type]

    def probe(self, running: object) -> OllamaReadinessStatus:
        return probe_instance_readiness(running, runtime=self._runtime)  # type: ignore[arg-type]

    def stop(self, running: object) -> None:
        stop_local_instance(running, runtime=self._runtime)  # type: ignore[arg-type]


class OllamaHostTransport:
    """Plan, apply, and probe one fixed Ollama operation on its selected host."""

    __slots__ = (
        "_registry",
        "_leases",
        "_local",
        "_remote",
        "_monotonic",
        "_apply_lock",
        "_applied",
        "_stopped",
    )

    def __init__(
        self,
        *,
        registry: OllamaRegistrySource,
        leases: OllamaHostLeaseSource | None = None,
        local: LocalOllamaHostAdapter | None = None,
        remote: RemoteOllamaOperationPort | None = None,
        monotonic=time.monotonic,
    ) -> None:
        self._registry = registry
        self._leases = leases
        self._local = local or Task3LocalOllamaHostAdapter()
        if remote is None:
            _fail("resource.host_unreachable")
        self._remote = remote
        self._monotonic = monotonic
        self._apply_lock = threading.RLock()
        self._applied: dict[str, OllamaHostExecution] = {}
        self._stopped: set[str] = set()

    def plan(
        self,
        instance: OllamaInstanceV1,
        *,
        generation: int,
        resource_generation: int | None = None,
    ) -> OllamaHostPlan | OperationV1:
        current = self._load_registry()
        if (
            type(instance) is not OllamaInstanceV1
            or type(generation) is not int
            or current.generation != generation
        ):
            _fail("control.plan_stale")
        _registry_with_instance(current, instance)
        lease = self._lease(instance.host_ref)
        idempotency_key = secrets.token_hex(32)
        document = _plan_document(
            instance, current.generation, lease, idempotency_key
        )
        plan_digest = _digest(document)
        document["plan_digest"] = plan_digest
        local_plan = None
        if instance.host_ref == CONTROL_HOST_REF:
            try:
                local_instance = replace(instance, host_ref="local")
                local_registry = _registry_with_instance(current, local_instance)
                local_plan = self._local.plan(local_instance, local_registry)
            except OllamaRuntimeError as error:
                raise OllamaHostError(error.code) from None
            except OllamaHostError:
                raise
            except Exception:
                _fail("resource.host_unreachable")
        else:
            remote = self._remote.plan(
                _remote_plan_request(
                    instance,
                    current,
                    lease,
                    document,
                    resource_generation=resource_generation,
                )
            )
            if type(remote) is not OperationV1:
                _fail("resource.host_response_invalid")
            return remote
        provenance = secrets.token_bytes(32)
        planned = OllamaHostPlan(
            1,
            instance.host_ref,
            instance.ref,
            current.generation,
            lease.runtime_generation,
            lease.fence,
            plan_digest,
            idempotency_key,
            lease.expires_at_monotonic,
            lease.lease_id,
            current,
            instance,
            local_plan,
            provenance,
            _PLAN_SEAL,
        )
        _register(_PLAN_RECORDS, provenance, planned, _plan_state(planned))
        return planned

    def apply(
        self, plan: OllamaHostPlan, *, current_fence: int
    ) -> OllamaHostExecution | OperationV1:
        with self._apply_lock:
            instance, lease = self._revalidate(plan, current_fence=current_fence)
            applied = self._applied.get(plan.idempotency_key)
            if applied is not None:
                return applied
            if plan.host_ref == CONTROL_HOST_REF:
                if plan._local_plan is None:
                    _fail("provider.plan_invalid")
                try:
                    runtime_value = self._local.apply(plan._local_plan)
                except OllamaRuntimeError as error:
                    raise OllamaHostError(error.code) from None
                except Exception:
                    _fail("resource.host_unreachable")
            else:
                remote = self._remote.apply(
                    OllamaRemoteApplyRequestV1(
                        plan.host_ref,
                        plan.instance_ref,
                        plan.model_generation,
                        None,
                        lease.fence,
                        plan.plan_digest,
                        plan.idempotency_key,
                        owner_plan_id=plan.idempotency_key,
                        owner_instance=_owner_instance_document(plan._instance),
                    )
                )
                if type(remote) is not OperationV1:
                    _fail("resource.host_response_invalid")
                return remote
            provenance = secrets.token_bytes(32)
            execution = OllamaHostExecution(
                plan, runtime_value, provenance, _EXECUTION_SEAL
            )
            _register(
                _EXECUTION_RECORDS,
                provenance,
                execution,
                _execution_state(execution),
            )
            self._applied[plan.idempotency_key] = execution
            return execution

    def probe(
        self, execution: OllamaHostExecution, *, current_fence: int
    ) -> OllamaReadinessStatus | OperationV1:
        if not _recorded(
            _EXECUTION_RECORDS,
            getattr(execution, "_provenance", b""),
            execution,
            _execution_state(execution) if isinstance(execution, OllamaHostExecution) else (),
        ):
            _fail("provider.instance_invalid")
        instance, lease = self._revalidate(
            execution.plan, current_fence=current_fence
        )
        if execution.plan.host_ref == CONTROL_HOST_REF:
            if execution._runtime_value is None:
                _fail("provider.instance_invalid")
            try:
                return self._local.probe(execution._runtime_value)
            except OllamaRuntimeError as error:
                raise OllamaHostError(error.code) from None
            except Exception:
                _fail("resource.host_unreachable")
        remote = self._remote.probe(
            OllamaRemoteProbeRequestV1(
                execution.plan.host_ref,
                execution.plan.instance_ref,
                execution.plan.model_generation,
                None,
                lease.fence,
                execution.plan.plan_digest,
                owner_plan_id=execution.plan.idempotency_key,
                owner_instance=_owner_instance_document(execution.plan._instance),
            )
        )
        if type(remote) is not OperationV1:
            _fail("resource.host_response_invalid")
        return remote

    def stop(
        self, execution: OllamaHostExecution, *, current_fence: int
    ) -> OperationV1 | None:
        with self._apply_lock:
            if not _recorded(
                _EXECUTION_RECORDS,
                getattr(execution, "_provenance", b""),
                execution,
                _execution_state(execution)
                if isinstance(execution, OllamaHostExecution)
                else (),
            ):
                _fail("provider.instance_invalid")
            instance, lease = self._revalidate(
                execution.plan, current_fence=current_fence
            )
            key = execution.plan.idempotency_key
            if key in self._stopped:
                return
            if execution.plan.host_ref == CONTROL_HOST_REF:
                if execution._runtime_value is None:
                    _fail("provider.instance_invalid")
                try:
                    self._local.stop(execution._runtime_value)
                except OllamaRuntimeError as error:
                    raise OllamaHostError(error.code) from None
                except Exception:
                    _fail("resource.host_unreachable")
            else:
                remote = self._remote.stop(
                    OllamaRemoteStopRequestV1(
                        execution.plan.host_ref,
                        execution.plan.instance_ref,
                        execution.plan.model_generation,
                        None,
                        lease.fence,
                        execution.plan.plan_digest,
                        owner_plan_id=execution.plan.idempotency_key,
                        owner_instance=_owner_instance_document(execution.plan._instance),
                    )
                )
                if type(remote) is not OperationV1:
                    _fail("resource.host_response_invalid")
                return remote
            self._stopped.add(key)

    def apply_remote(
        self,
        instance: OllamaInstanceV1,
        *,
        generation: int,
        resource_generation: int | None,
        plan_digest: str,
        plan_ref: str,
        plan_precondition_digest: str | None = None,
        owner_plan_id: str | None = None,
    ) -> OperationV1:
        lease = self._lease(instance.host_ref)
        result = self._remote.apply(
            OllamaRemoteApplyRequestV1(
                instance.host_ref,
                instance.ref,
                generation,
                resource_generation,
                lease.fence,
                plan_digest,
                plan_ref,
                plan_precondition_digest,
                owner_plan_id,
                _owner_instance_document(instance),
            )
        )
        if type(result) is not OperationV1:
            _fail("resource.host_response_invalid")
        return result

    def probe_remote(
        self,
        instance: OllamaInstanceV1,
        *,
        generation: int,
        resource_generation: int | None,
        plan_digest: str,
        plan_precondition_digest: str | None = None,
        owner_plan_id: str | None = None,
    ) -> OperationV1:
        lease = self._lease(instance.host_ref)
        result = self._remote.probe(
            OllamaRemoteProbeRequestV1(
                instance.host_ref,
                instance.ref,
                generation,
                resource_generation,
                lease.fence,
                plan_digest,
                plan_precondition_digest,
                owner_plan_id,
                _owner_instance_document(instance),
            )
        )
        if type(result) is not OperationV1:
            _fail("resource.host_response_invalid")
        return result

    def stop_remote(
        self,
        instance: OllamaInstanceV1,
        *,
        generation: int,
        resource_generation: int | None,
        plan_digest: str,
        plan_precondition_digest: str | None = None,
        owner_plan_id: str | None = None,
    ) -> OperationV1:
        lease = self._lease(instance.host_ref)
        result = self._remote.stop(
            OllamaRemoteStopRequestV1(
                instance.host_ref,
                instance.ref,
                generation,
                resource_generation,
                lease.fence,
                plan_digest,
                plan_precondition_digest,
                owner_plan_id,
                _owner_instance_document(instance),
            )
        )
        if type(result) is not OperationV1:
            _fail("resource.host_response_invalid")
        return result

    def _load_registry(self) -> OllamaRegistryV1:
        try:
            current = self._registry.load()
        except Exception:
            _fail("control.plan_stale")
        if type(current) is not OllamaRegistryV1:
            _fail("control.plan_stale")
        return current

    def _lease(self, host_ref: str) -> OllamaHostLease:
        if self._leases is None:
            return OllamaHostLease(
                host_ref,
                "adapter-fence",
                1,
                1,
                float(self._monotonic()) + 365 * 24 * 60 * 60,
            )
        try:
            lease = self._leases.resolve(host_ref)
            now = self._monotonic()
        except Exception:
            _fail("resource.host_unreachable")
        if type(lease) is not OllamaHostLease or lease.host_ref != host_ref:
            _fail("resource.host_unreachable")
        lease.__post_init__()
        if type(now) not in (int, float) or not math.isfinite(float(now)):
            _fail("resource.host_unreachable")
        if float(now) >= lease.expires_at_monotonic:
            _fail("control.plan_stale")
        return lease

    def _revalidate(
        self, plan: OllamaHostPlan, *, current_fence: int
    ) -> tuple[OllamaInstanceV1, OllamaHostLease]:
        if (
            type(plan) is not OllamaHostPlan
            or not _recorded(
                _PLAN_RECORDS,
                plan._provenance,
                plan,
                _plan_state(plan),
            )
            or type(current_fence) is not int
            or current_fence != plan.fence
        ):
            _fail("control.plan_stale")
        current = self._load_registry()
        instance = plan._instance
        lease = self._lease(plan.host_ref)
        if (
            current != plan._registry
            or current.generation != plan.model_generation
            or instance.host_ref != plan.host_ref
            or lease.lease_id != plan.lease_id
            or lease.runtime_generation != plan.runtime_generation
            or lease.fence != plan.fence
            or lease.expires_at_monotonic != plan.expires_at_monotonic
            or _digest(
                _plan_document(
                    instance,
                    current.generation,
                    lease,
                    plan.idempotency_key,
                )
            )
            != plan.plan_digest
        ):
            _fail("control.plan_stale")
        return instance, lease


def _remote_plan_request(
    instance: OllamaInstanceV1,
    registry: OllamaRegistryV1,
    lease: OllamaHostLease,
    document: Mapping[str, object],
    *,
    resource_generation: int | None,
) -> OllamaRemotePlanRequestV1:
    plan_digest = document.get("plan_digest")
    idempotency_key = document.get("idempotency_key")
    if type(plan_digest) is not str or type(idempotency_key) is not str:
        _fail("provider.operation_not_allowed")
    return OllamaRemotePlanRequestV1(
        instance.host_ref,
        instance.ref,
        registry.generation,
        lease.runtime_generation,
        lease.fence,
        lease.fence,
        plan_digest,
        idempotency_key,
        instance.selected_model_refs,
        instance.allowed_cpus,
        instance.cpu_quota_percent,
        instance.cpu_weight,
        resource_generation,
        _owner_instance_document(instance),
    )


def _validate_remote_request(
    action: str,
    request: (
        OllamaRemotePlanRequestV1
        | OllamaRemoteApplyRequestV1
        | OllamaRemoteProbeRequestV1
        | OllamaRemoteStopRequestV1
    ),
) -> None:
    expected_type = {
        "plan": OllamaRemotePlanRequestV1,
        "apply": OllamaRemoteApplyRequestV1,
        "probe": OllamaRemoteProbeRequestV1,
        "stop": OllamaRemoteStopRequestV1,
    }.get(action)
    if type(request) is not expected_type:
        _fail("provider.operation_not_allowed")
    if (
        not _safe_token(request.host_ref)
        or not _safe_token(request.instance_ref)
        or type(request.registry_generation) is not int
        or request.registry_generation < 0
        or type(request.lease_epoch) is not int
        or request.lease_epoch <= 0
        or not _hex_token(request.plan_digest, 64)
    ):
        _fail("provider.operation_not_allowed")
    if type(request) is OllamaRemotePlanRequestV1:
        if (
            type(request.runtime_generation) is not int
            or request.runtime_generation < 0
            or type(request.fence) is not int
            or request.fence < 0
            or not _hex_token(request.idempotency_key, 64)
            or not request.selected_model_refs
            or any(not _safe_token(item) for item in request.selected_model_refs)
            or type(request.allowed_cpus) is not str
            or type(request.cpu_quota_percent) is not int
            or type(request.cpu_weight) is not int
            or (
                request.resource_generation is not None
                and (
                    type(request.resource_generation) is not int
                    or request.resource_generation < 0
                )
            )
        ):
            _fail("provider.operation_not_allowed")
    elif type(request) is OllamaRemoteApplyRequestV1 and not _safe_token(
        request.plan_ref
    ):
        _fail("provider.operation_not_allowed")
    if (
        not isinstance(request, OllamaRemotePlanRequestV1)
        and not _safe_token(request.owner_plan_id)
    ):
        _fail("provider.operation_not_allowed")
    if (
        not isinstance(request, OllamaRemotePlanRequestV1)
        and request.resource_generation is not None
        and (
            type(request.resource_generation) is not int
            or request.resource_generation < 0
        )
    ):
        _fail("provider.operation_not_allowed")
    if (
        not isinstance(request, OllamaRemotePlanRequestV1)
        and request.plan_precondition_digest is not None
        and not _hex_token(request.plan_precondition_digest, 64)
    ):
        _fail("provider.operation_not_allowed")


def _request_resource_generation(
    request: (
        OllamaRemotePlanRequestV1
        | OllamaRemoteApplyRequestV1
        | OllamaRemoteProbeRequestV1
        | OllamaRemoteStopRequestV1
    ),
) -> int | None:
    return request.resource_generation


def _request_plan_precondition_digest(
    request: (
        OllamaRemotePlanRequestV1
        | OllamaRemoteApplyRequestV1
        | OllamaRemoteProbeRequestV1
        | OllamaRemoteStopRequestV1
    ),
) -> str:
    if isinstance(request, OllamaRemotePlanRequestV1):
        return request.plan_digest
    return request.plan_precondition_digest or request.plan_digest


def _operation_from_agent_view(value: object) -> OperationV1:
    state = getattr(value, "state", None)
    if state == "leased":
        state = "running"
    if state not in {"queued", "running", "succeeded", "failed", "unknown"}:
        _fail("resource.host_response_invalid")
    created_at = getattr(value, "created_at", None)
    deadline = getattr(value, "deadline", None)
    operation_id = getattr(value, "operation_id", None)
    registry_generation = getattr(value, "registry_generation", None)
    plan_digest = getattr(value, "plan_digest", None)
    attempt = getattr(value, "attempt", None)
    action = getattr(value, "action", None)
    reasons = getattr(value, "reason_codes", ())
    if (
        type(created_at) is not datetime
        or type(deadline) is not datetime
        or type(operation_id) is not str
        or type(registry_generation) is not int
        or type(plan_digest) is not str
        or type(attempt) is not int
        or action not in {"plan", "apply", "probe", "stop"}
        or type(reasons) is not tuple
    ):
        _fail("resource.host_response_invalid")
    return OperationV1(
        operation_id,
        "ollama.instance." + action,
        state,
        registry_generation,
        registry_generation if state == "succeeded" else None,
        plan_digest,
        created_at,
        deadline,
        1 if state == "succeeded" else 0,
        1 if state in {"failed", "unknown"} else 0,
        0 if state in {"succeeded", "failed", "unknown"} else 1,
        reasons if state in {"succeeded", "failed", "unknown"} else ("control.operation_queued",),
    )


def _registry_with_instance(
    registry: OllamaRegistryV1, instance: OllamaInstanceV1
) -> OllamaRegistryV1:
    replaced = False
    instances = []
    for candidate in registry.instances:
        if candidate.ref == instance.ref:
            instances.append(instance)
            replaced = True
        else:
            instances.append(candidate)
    if not replaced:
        instances.append(instance)
    try:
        return replace(registry, instances=tuple(instances))
    except Exception:
        _fail("provider.instance_invalid")


def _plan_document(
    instance: OllamaInstanceV1,
    model_generation: int,
    lease: OllamaHostLease,
    idempotency_key: str,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "operation_type": OLLAMA_OPERATION_TYPE,
        "host_ref": instance.host_ref,
        "instance_ref": instance.ref,
        "selected_model_refs": list(instance.selected_model_refs),
        "allowed_cpus": instance.allowed_cpus,
        "cpu_quota_percent": instance.cpu_quota_percent,
        "cpu_weight": instance.cpu_weight,
        "model_generation": model_generation,
        "runtime_generation": lease.runtime_generation,
        "fence": lease.fence,
        "idempotency_key": idempotency_key,
    }


def _hex_token(value: object, length: int) -> bool:
    return (
        type(value) is str
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def _safe_model_id(value: object) -> bool:
    return (
        type(value) is str
        and 0 < len(value) <= 512
        and not value.startswith("/")
        and "\\" not in value
        and all(component not in ("", ".", "..") for component in value.split("/"))
        and all(
            character.isascii()
            and (character.isalnum() or character in "._:/-@")
            for character in value
        )
    )


def _plan_state(plan: OllamaHostPlan) -> tuple[object, ...]:
    return (
        plan.schema_version,
        plan.host_ref,
        plan.instance_ref,
        plan.model_generation,
        plan.runtime_generation,
        plan.fence,
        plan.plan_digest,
        plan.idempotency_key,
        plan.expires_at_monotonic,
        plan.lease_id,
        plan._registry,
        plan._instance,
        id(plan._local_plan),
        plan._provenance,
        id(plan._seal),
    )


def _execution_state(execution: OllamaHostExecution) -> tuple[object, ...]:
    return (
        id(execution.plan),
        id(execution._runtime_value),
        execution._provenance,
        id(execution._seal),
    )


def _register(
    records: dict[bytes, tuple[weakref.ReferenceType[object], tuple[object, ...]]],
    provenance: bytes,
    value: object,
    state: tuple[object, ...],
) -> None:
    def discard(reference: weakref.ReferenceType[object]) -> None:
        with _RECORD_LOCK:
            current = records.get(provenance)
            if current is not None and current[0] is reference:
                records.pop(provenance, None)

    with _RECORD_LOCK:
        records[provenance] = (weakref.ref(value, discard), state)


def _recorded(
    records: dict[bytes, tuple[weakref.ReferenceType[object], tuple[object, ...]]],
    provenance: bytes,
    value: object,
    state: tuple[object, ...],
) -> bool:
    with _RECORD_LOCK:
        record = records.get(provenance)
        return record is not None and record[0]() is value and record[1] == state


__all__ = (
    "CONTROL_HOST_REF",
    "OLLAMA_OPERATION_TYPE",
    "OllamaHostError",
    "OllamaHostLease",
    "OllamaHostPlan",
    "OllamaHostExecution",
    "OllamaRegistrySource",
    "OllamaHostLeaseSource",
    "LocalOllamaHostAdapter",
    "OllamaRemotePlanRequestV1",
    "OllamaRemoteApplyRequestV1",
    "OllamaRemoteProbeRequestV1",
    "OllamaRemoteStopRequestV1",
    "RemoteOllamaOperationPort",
    "AgentQueueRemoteOllamaOperationPort",
    "HostRegistryOllamaLeaseSource",
    "Task3LocalOllamaHostAdapter",
    "OllamaHostTransport",
)
