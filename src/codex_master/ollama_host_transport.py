"""Typed, fenced Ollama placement over local or registered host adapters."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import hashlib
import json
import math
import secrets
import threading
import time
from typing import NoReturn, Protocol
import weakref

from codex_master.fleet_home_broker_transport import (
    BrokerOllamaInstancePayload,
    BrokerOperationClient,
    BrokerOperationRequest,
    BrokerTransportError,
    exchange_typed_operation,
)
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


class Task3LocalOllamaHostAdapter:
    """Thin control-host adapter over Task 3's hardened local runtime."""

    __slots__ = ("_runtime",)

    def __init__(self, runtime: OllamaRuntime | None = None) -> None:
        self._runtime = runtime

    def plan(
        self, instance: OllamaInstanceV1, registry: OllamaRegistryV1
    ) -> object:
        local_instance = replace(instance, host_ref="local")
        local_registry = replace(
            registry,
            instances=tuple(
                local_instance if candidate.ref == instance.ref else candidate
                for candidate in registry.instances
            ),
        )
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
        "_broker",
        "_local",
        "_monotonic",
        "_apply_lock",
        "_applied",
        "_stopped",
    )

    def __init__(
        self,
        *,
        registry: OllamaRegistrySource,
        leases: OllamaHostLeaseSource,
        broker: BrokerOperationClient,
        local: LocalOllamaHostAdapter | None = None,
        monotonic=time.monotonic,
    ) -> None:
        self._registry = registry
        self._leases = leases
        self._broker = broker
        self._local = local or Task3LocalOllamaHostAdapter()
        self._monotonic = monotonic
        self._apply_lock = threading.RLock()
        self._applied: dict[str, OllamaHostExecution] = {}
        self._stopped: set[str] = set()

    def plan(self, instance: OllamaInstanceV1, *, generation: int) -> OllamaHostPlan:
        current = self._load_registry()
        if (
            type(instance) is not OllamaInstanceV1
            or type(generation) is not int
            or current.generation != generation
            or _registry_instance(current, instance.ref) != instance
        ):
            _fail("control.plan_stale")
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
                local_registry = replace(
                    current,
                    instances=tuple(
                        local_instance if candidate.ref == instance.ref else candidate
                        for candidate in current.instances
                    ),
                )
                local_plan = self._local.plan(local_instance, local_registry)
            except OllamaRuntimeError as error:
                raise OllamaHostError(error.code) from None
            except OllamaHostError:
                raise
            except Exception:
                _fail("resource.host_unreachable")
        else:
            self._remote("plan", lease, document, expected_status="planned")
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
            local_plan,
            provenance,
            _PLAN_SEAL,
        )
        _register(_PLAN_RECORDS, provenance, planned, _plan_state(planned))
        return planned

    def apply(
        self, plan: OllamaHostPlan, *, current_fence: int
    ) -> OllamaHostExecution:
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
                self._remote(
                    "apply",
                    lease,
                    _bound_document(plan, instance),
                    expected_status="running",
                )
                runtime_value = None
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
    ) -> OllamaReadinessStatus:
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
        document = self._remote(
            "probe",
            lease,
            _bound_document(execution.plan, instance),
            expected_status=("ready", "not_ready"),
        )
        return _readiness(document)

    def stop(self, execution: OllamaHostExecution, *, current_fence: int) -> None:
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
                self._remote(
                    "stop",
                    lease,
                    _bound_document(execution.plan, instance),
                    expected_status="stopped",
                )
            self._stopped.add(key)

    def _load_registry(self) -> OllamaRegistryV1:
        try:
            current = self._registry.load()
        except Exception:
            _fail("control.plan_stale")
        if type(current) is not OllamaRegistryV1:
            _fail("control.plan_stale")
        return current

    def _lease(self, host_ref: str) -> OllamaHostLease:
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
        instance = _registry_instance(current, plan.instance_ref)
        lease = self._lease(plan.host_ref)
        if (
            instance is None
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

    def _remote(
        self,
        action: str,
        lease: OllamaHostLease,
        document: dict[str, object],
        *,
        expected_status: str | tuple[str, ...],
    ) -> dict[str, object]:
        request = BrokerOperationRequest(
            1,
            OLLAMA_OPERATION_TYPE,
            action,
            lease.host_ref,
            lease.lease_id,
            secrets.token_hex(16),
            _broker_payload(document),
        )
        try:
            response = exchange_typed_operation(self._broker, request)
        except BrokerTransportError as error:
            raise OllamaHostError(str(error)) from None
        try:
            value = json.loads(response.payload.decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            _fail("resource.host_response_invalid")
        statuses = (
            (expected_status,) if isinstance(expected_status, str) else expected_status
        )
        required = {"schema_version", "status", "plan_digest"}
        if (
            type(value) is not dict
            or not required.issubset(value)
            or value["schema_version"] != 1
            or value["status"] not in statuses
            or value["plan_digest"] != document.get("plan_digest")
        ):
            _fail("resource.host_response_invalid")
        if action == "probe":
            if set(value) != {
                *required,
                "ready",
                "reason_codes",
                "process_running",
                "cgroup_member",
                "loopback_endpoint_reachable",
                "available_model_ids",
            }:
                _fail("resource.host_response_invalid")
        elif set(value) != required:
            _fail("resource.host_response_invalid")
        return value


def _registry_instance(
    registry: OllamaRegistryV1, instance_ref: str
) -> OllamaInstanceV1 | None:
    matches = tuple(instance for instance in registry.instances if instance.ref == instance_ref)
    return matches[0] if len(matches) == 1 else None


def _broker_payload(document: dict[str, object]) -> BrokerOllamaInstancePayload:
    expected = {
        "schema_version",
        "operation_type",
        "host_ref",
        "instance_ref",
        "selected_model_refs",
        "allowed_cpus",
        "cpu_quota_percent",
        "cpu_weight",
        "model_generation",
        "runtime_generation",
        "fence",
        "plan_digest",
        "idempotency_key",
    }
    host_ref = document.get("host_ref")
    instance_ref = document.get("instance_ref")
    selected = document.get("selected_model_refs")
    allowed_cpus = document.get("allowed_cpus")
    cpu_quota = document.get("cpu_quota_percent")
    cpu_weight = document.get("cpu_weight")
    model_generation = document.get("model_generation")
    runtime_generation = document.get("runtime_generation")
    fence = document.get("fence")
    plan_digest = document.get("plan_digest")
    idempotency_key = document.get("idempotency_key")
    if (
        set(document) != expected
        or document.get("schema_version") != 1
        or document.get("operation_type") != OLLAMA_OPERATION_TYPE
        or type(host_ref) is not str
        or type(instance_ref) is not str
        or type(selected) is not list
        or any(type(model_ref) is not str for model_ref in selected)
        or type(allowed_cpus) is not str
        or type(cpu_quota) is not int
        or type(cpu_weight) is not int
        or type(model_generation) is not int
        or type(runtime_generation) is not int
        or type(fence) is not int
        or type(plan_digest) is not str
        or type(idempotency_key) is not str
    ):
        _fail("provider.operation_not_allowed")
    try:
        return BrokerOllamaInstancePayload(
            host_ref,
            instance_ref,
            tuple(selected),
            allowed_cpus,
            cpu_quota,
            cpu_weight,
            model_generation,
            runtime_generation,
            fence,
            plan_digest,
            idempotency_key,
        )
    except BrokerTransportError:
        _fail("provider.operation_not_allowed")


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


def _bound_document(
    plan: OllamaHostPlan, instance: OllamaInstanceV1
) -> dict[str, object]:
    document = _plan_document(
        instance,
        plan.model_generation,
        OllamaHostLease(
            plan.host_ref,
            plan.lease_id,
            plan.runtime_generation,
            plan.fence,
            plan.expires_at_monotonic,
        ),
        plan.idempotency_key,
    )
    document["plan_digest"] = plan.plan_digest
    return document


def _readiness(document: dict[str, object]) -> OllamaReadinessStatus:
    ready = document.get("ready")
    reasons = document.get("reason_codes")
    models = document.get("available_model_ids")
    process_running = document.get("process_running")
    cgroup_member = document.get("cgroup_member")
    endpoint = document.get("loopback_endpoint_reachable")
    if (
        type(ready) is not bool
        or type(reasons) is not list
        or len(reasons) > 16
        or any(not _safe_token(reason) for reason in reasons)
        or type(models) is not list
        or len(models) > 1024
        or any(not _safe_model_id(model) for model in models)
        or type(process_running) is not bool
        or type(cgroup_member) is not bool
        or type(endpoint) is not bool
        or ready != (document.get("status") == "ready")
        or (
            ready
            and (
                reasons
                or not models
                or not all((process_running, cgroup_member, endpoint))
            )
        )
        or (not ready and not reasons)
    ):
        _fail("resource.host_response_invalid")
    return OllamaReadinessStatus(
        ready,
        tuple(reasons),
        process_running,
        cgroup_member,
        endpoint,
        tuple(models),
    )


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
    "Task3LocalOllamaHostAdapter",
    "OllamaHostTransport",
)
