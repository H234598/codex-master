from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from codex_master.ollama_host_transport import (
    AgentQueueRemoteOllamaOperationPort,
    CONTROL_HOST_REF,
    HostRegistryOllamaLeaseSource,
    OllamaHostError,
    OllamaHostLease,
    OllamaHostPlan,
    OllamaHostTransport,
    OllamaRemoteApplyRequestV1,
    OllamaRemotePlanRequestV1,
    OllamaRemoteProbeRequestV1,
    OllamaRemoteStopRequestV1,
    Task3LocalOllamaHostAdapter,
)
from codex_master.ollama_registry import (
    OllamaInstanceV1,
    OllamaModelV1,
    OllamaRegistryV1,
)
from codex_master.ollama_runtime import OllamaReadinessStatus
from codex_master.admin_contracts import OperationV1
from codex_master.admin_hosts import AgentBindingV1, HostRegistry
from codex_master.agent_operations import (
    AgentOperationStore,
    AgentPrincipalV1,
)
from codex_master.agent_contracts import AgentNoWorkV1, AgentPollV1


MODEL_GENERATION = 8
RUNTIME_GENERATION = 13
FENCE = 3
LEASE_ID = "lease-" + "a" * 32


def model(ref: str = "llama-small") -> OllamaModelV1:
    return OllamaModelV1(ref, f"provider-{ref}", True, True, True, "fresh")


def instance(
    host_ref: str = "worker-west",
    *,
    executable: str = "/private/worker/ollama",
    models_directory: str = "/private/worker/models",
) -> OllamaInstanceV1:
    return OllamaInstanceV1(
        ref="ollama-west",
        label="West",
        host_ref=host_ref,
        ollama_executable=executable,
        models_directory=models_directory,
        selected_model_refs=("llama-small",),
        allowed_cpus="2-3",
        cpu_quota_percent=200,
        cpu_weight=50,
        lifecycle_state="planned",
        readiness_state="unknown",
    )


def registry(placed: OllamaInstanceV1) -> OllamaRegistryV1:
    return OllamaRegistryV1(1, MODEL_GENERATION, (model(),), (placed,))


def _agent_host_registry(tmp_path: Path) -> HostRegistry:
    hosts = HostRegistry.for_test(tmp_path / "hosts")
    hosts.provision_agent_binding(
        {
            "ref": "worker-west",
            "label": "Worker West",
            "role": "execution",
            "capabilities": ["ollama.execute", "resource.probe"],
        },
        AgentBindingV1("worker-west", "sha256:" + "a" * 64, 3, True),
        expected_generation=0,
    )
    return hosts


@dataclass
class RegistrySource:
    value: OllamaRegistryV1

    def load(self) -> OllamaRegistryV1:
        return self.value


@dataclass
class LeaseSource:
    value: OllamaHostLease | None

    def resolve(self, host_ref: str) -> OllamaHostLease | None:
        if self.value is None or self.value.host_ref != host_ref:
            return None
        return self.value


class FakeLocalAdapter:
    def __init__(self) -> None:
        self.calls = []
        self.local_plan = object()
        self.running = object()

    def plan(self, placed, current_registry):
        self.calls.append(("plan", placed, current_registry))
        return self.local_plan

    def apply(self, planned):
        self.calls.append(("apply", planned))
        return self.running

    def probe(self, running):
        self.calls.append(("probe", running))
        return OllamaReadinessStatus(True, (), True, True, True, ("provider-llama-small",))

    def stop(self, running):
        self.calls.append(("stop", running))


class _RecordingAgentStore:
    def __init__(self) -> None:
        self.enqueued_actions: list[tuple[str, str]] = []


class _QueuedRemoteOllamaPort:
    """Real transport-shaped double: only the remote side sees the queue."""

    def __init__(self) -> None:
        self.agent_store = _RecordingAgentStore()

    def plan(self, request):
        self.agent_store.enqueued_actions.append(("ollama.instance", "plan"))
        return OperationV1(
            "operation-remote-plan",
            "ollama.instance.plan",
            "queued",
            request.registry_generation,
            None,
            "sha256:" + request.plan_digest,
            datetime(2026, 8, 30, tzinfo=UTC),
            datetime(2026, 8, 30, tzinfo=UTC) + timedelta(minutes=5),
            0,
            0,
            1,
            ("control.operation_queued",),
        )


class _MappingRemoteOllamaPort:
    """Deliberately invalid legacy response shape; the product edge is OperationV1."""

    def plan(self, request):
        return {
            "schema_version": 1,
            "status": "planned",
            "plan_digest": request.plan_digest,
        }

    def apply(self, request):
        del request
        return {"status": "running"}

    def probe(self, request):
        del request
        return {"status": "ready"}

    def stop(self, request):
        del request
        return {"status": "stopped"}


class _OperationRemoteOllamaPort:
    """Strict remote contract double for local-adapter separation tests."""

    @staticmethod
    def _operation(request, action):
        return OperationV1(
            "operation-remote-" + action,
            "ollama.instance." + action,
            "queued",
            request.registry_generation,
            None,
            "sha256:" + request.plan_digest,
            datetime(2026, 8, 30, tzinfo=UTC),
            datetime(2026, 8, 30, tzinfo=UTC) + timedelta(minutes=5),
            0,
            0,
            1,
            ("control.operation_queued",),
        )

    def plan(self, request):
        return self._operation(request, "plan")

    def apply(self, request):
        return self._operation(request, "apply")

    def probe(self, request):
        return self._operation(request, "probe")

    def stop(self, request):
        return self._operation(request, "stop")


def lease(host_ref: str, *, fence: int = FENCE, expires_at: float = 200.0):
    return OllamaHostLease(
        host_ref=host_ref,
        lease_id=LEASE_ID,
        runtime_generation=RUNTIME_GENERATION,
        fence=fence,
        expires_at_monotonic=expires_at,
    )


def test_remote_plan_enqueues_and_local_plan_stays_direct() -> None:
    local_instance = replace(instance(CONTROL_HOST_REF), ref="ollama-control")
    remote_instance = replace(instance("worker-west"), ref="ollama-worker-west")
    source = RegistrySource(
        OllamaRegistryV1(1, MODEL_GENERATION, (model(),), (local_instance, remote_instance))
    )
    remote = _QueuedRemoteOllamaPort()
    local = FakeLocalAdapter()

    transport = OllamaHostTransport(
        registry=source,
        local=local,
        remote=remote,
        monotonic=lambda: 100.0,
    )

    planned_local = transport.plan(local_instance, generation=MODEL_GENERATION)
    planned_remote = transport.plan(remote_instance, generation=MODEL_GENERATION)

    assert isinstance(planned_local, OllamaHostPlan)
    assert planned_remote.state == "queued"
    assert [call[0] for call in local.calls] == ["plan"]
    assert remote.agent_store.enqueued_actions == [("ollama.instance", "plan")]


def test_remote_transport_rejects_legacy_synchronous_mapping_response() -> None:
    placed = instance("worker-west")
    transport = OllamaHostTransport(
        registry=RegistrySource(registry(placed)),
        leases=LeaseSource(lease("worker-west")),
        local=FakeLocalAdapter(),
        remote=_MappingRemoteOllamaPort(),
        monotonic=lambda: 100.0,
    )

    with pytest.raises(OllamaHostError, match=r"^resource\.host_response_invalid$"):
        transport.plan(placed, generation=MODEL_GENERATION)


def test_agent_queue_port_enqueues_only_remote_ollama_plan(tmp_path: Path) -> None:
    hosts = _agent_host_registry(tmp_path)
    agent_store = AgentOperationStore.for_test(tmp_path / "agent-operations")
    local_adapter = FakeLocalAdapter()
    local_instance = replace(instance(CONTROL_HOST_REF), ref="ollama-control")
    remote_instance = replace(instance(), ref="ollama-worker-west")
    transport = OllamaHostTransport(
        registry=RegistrySource(registry(remote_instance)),
        leases=HostRegistryOllamaLeaseSource(hosts),
        local=local_adapter,
        remote=AgentQueueRemoteOllamaOperationPort(
            agent_operations=agent_store, host_registry=hosts
        ),
    )

    local = transport.plan(local_instance, generation=MODEL_GENERATION)
    remote = transport.plan(remote_instance, generation=MODEL_GENERATION)

    assert isinstance(local, OllamaHostPlan)
    assert remote.state == "queued"
    assert local_adapter.calls[0][0] == "plan"
    queued = agent_store.get(remote.id)
    assert (queued.kind, queued.action) == (
        "ollama.instance",
        "plan",
    )
    assert queued.plan_digest == remote.plan_digest
    leased = agent_store.poll(
        AgentPrincipalV1("worker-west", hosts.document_generation()),
        AgentPollV1(
            hosts.document_generation(), 3, "sha256:" + "c" * 64, 0
        ),
    )
    assert leased.host_ref == "worker-west"


def test_agent_queue_port_uses_the_fixed_agent_allowlist_and_epoch(tmp_path: Path) -> None:
    hosts = _agent_host_registry(tmp_path)
    store = AgentOperationStore.for_test(tmp_path / "agent-operations")
    port = AgentQueueRemoteOllamaOperationPort(
        agent_operations=store, host_registry=hosts
    )
    digest = "b" * 64
    plan = port.plan(
        OllamaRemotePlanRequestV1(
            "worker-west", "ollama-worker-west", 8, 13, 3, 3, digest,
            "a" * 64, ("llama-small",), "2-3", 200, 50,
        )
    )
    apply = port.apply(
        OllamaRemoteApplyRequestV1(
            "worker-west", "ollama-worker-west", 8, None, 3, digest, "plan-one"
        )
    )
    probe = port.probe(
        OllamaRemoteProbeRequestV1(
            "worker-west", "ollama-worker-west", 8, None, 3, digest
        )
    )
    stopped = port.stop(
        OllamaRemoteStopRequestV1(
            "worker-west", "ollama-worker-west", 8, None, 3, digest
        )
    )

    queued = tuple(store.get(operation.id) for operation in (plan, apply, probe, stopped))
    assert [(item.kind, item.action) for item in queued] == [
        ("ollama.instance", "plan"),
        ("ollama.instance", "apply"),
        ("ollama.instance", "probe"),
        ("ollama.instance", "stop"),
    ]
    leases = tuple(
        store.poll(
            AgentPrincipalV1("worker-west", hosts.document_generation()),
            AgentPollV1(
                hosts.document_generation(), 3, "sha256:" + "c" * 64, 0
            ),
        )
        for _ in queued
    )
    assert [dict(item.arguments) for item in leases] == [
        {"generation": 8, "instance_ref": "ollama-worker-west"},
        {"plan_ref": "plan-one"},
        {"generation": 8, "instance_ref": "ollama-worker-west"},
        {"generation": 8, "instance_ref": "ollama-worker-west"},
    ]
    with pytest.raises(OllamaHostError, match=r"^control\.plan_stale$"):
        port.probe(
            OllamaRemoteProbeRequestV1(
                "worker-west", "ollama-worker-west", 8, None, 4, digest
            )
        )


def test_remote_queue_terminalizes_epoch_rotated_operation_before_lease(
    tmp_path: Path,
) -> None:
    hosts = _agent_host_registry(tmp_path)
    store = AgentOperationStore.for_test(tmp_path / "agent-operations")
    port = AgentQueueRemoteOllamaOperationPort(
        agent_operations=store, host_registry=hosts
    )
    operation = port.plan(
        OllamaRemotePlanRequestV1(
            "worker-west",
            "ollama-worker-west",
            8,
            13,
            3,
            3,
            "b" * 64,
            "a" * 64,
            ("llama-small",),
            "2-3",
            200,
            50,
        )
    )

    hosts.provision_agent_binding(
        {
            "ref": "worker-west",
            "label": "Worker West",
            "role": "execution",
            "capabilities": ["ollama.execute", "resource.probe"],
        },
        AgentBindingV1("worker-west", "sha256:" + "b" * 64, 1, True),
        expected_generation=hosts.document_generation(),
    )

    no_work = store.poll(
        AgentPrincipalV1("worker-west", hosts.document_generation()),
        AgentPollV1(
            hosts.document_generation(), 4, "sha256:" + "c" * 64, 0
        ),
    )

    assert type(no_work) is AgentNoWorkV1
    stale = store.get(operation.id)
    assert stale.state == "failed"
    assert stale.reason_codes == ("host.registry_generation_stale",)


def test_control_host_uses_local_task3_adapter_without_agent_queue_call():
    placed = instance(CONTROL_HOST_REF)
    local = FakeLocalAdapter()
    transport = OllamaHostTransport(
        registry=RegistrySource(registry(placed)),
        leases=LeaseSource(lease(CONTROL_HOST_REF)),
        remote=_OperationRemoteOllamaPort(),
        local=local,
        monotonic=lambda: 100.0,
    )

    planned = transport.plan(placed, generation=MODEL_GENERATION)
    execution = transport.apply(planned, current_fence=FENCE)
    readiness = transport.probe(execution, current_fence=FENCE)

    assert [call[0] for call in local.calls] == ["plan", "apply", "probe"]
    assert local.calls[0][1].host_ref == "local"
    assert readiness.ready is True


def test_successful_local_apply_retry_returns_same_execution_without_second_effect():
    placed = instance(CONTROL_HOST_REF)
    local = FakeLocalAdapter()
    transport = OllamaHostTransport(
        registry=RegistrySource(registry(placed)),
        leases=LeaseSource(lease(CONTROL_HOST_REF)),
        remote=_OperationRemoteOllamaPort(),
        local=local,
        monotonic=lambda: 100.0,
    )
    planned = transport.plan(placed, generation=MODEL_GENERATION)

    first = transport.apply(planned, current_fence=FENCE)
    second = transport.apply(planned, current_fence=FENCE)

    assert second is first
    assert [call[0] for call in local.calls] == ["plan", "apply"]


def test_local_stop_targets_only_execution_created_by_transport():
    placed = instance(CONTROL_HOST_REF)
    local = FakeLocalAdapter()
    transport = OllamaHostTransport(
        registry=RegistrySource(registry(placed)),
        leases=LeaseSource(lease(CONTROL_HOST_REF)),
        remote=_OperationRemoteOllamaPort(),
        local=local,
        monotonic=lambda: 100.0,
    )
    planned = transport.plan(placed, generation=MODEL_GENERATION)
    execution = transport.apply(planned, current_fence=FENCE)

    transport.stop(execution, current_fence=FENCE)
    transport.stop(execution, current_fence=FENCE)
    assert [call[0] for call in local.calls] == ["plan", "apply", "stop"]

def test_local_plan_provenance_is_not_copied_or_serialized():
    class NonCopyable:
        def __deepcopy__(self, memo):
            raise AssertionError("runtime provenance copied")

    placed = instance(CONTROL_HOST_REF)
    local = FakeLocalAdapter()
    transport = OllamaHostTransport(
        registry=RegistrySource(registry(placed)),
        leases=LeaseSource(lease(CONTROL_HOST_REF)),
        remote=_OperationRemoteOllamaPort(),
        local=local,
        monotonic=lambda: 100.0,
    )
    local.local_plan = NonCopyable()

    planned = transport.plan(placed, generation=MODEL_GENERATION)

    assert planned.host_ref == CONTROL_HOST_REF


def test_default_control_adapter_calls_task3_local_planner(tmp_path):
    executable = tmp_path / "ollama"
    executable.write_bytes(b"#!/bin/sh\nexit 0\n")
    executable.chmod(0o700)
    models_directory = tmp_path / "models"
    models_directory.mkdir(mode=0o700)
    placed = instance(
        CONTROL_HOST_REF,
        executable=str(executable),
        models_directory=str(models_directory),
    )

    class PlanRuntime:
        def available_cpus(self):
            return (0, 1, 2, 3)

    adapter = Task3LocalOllamaHostAdapter(runtime=PlanRuntime())
    planned = adapter.plan(placed, registry(placed))

    assert planned.instance.host_ref == "local"
    assert planned.executable.path == str(executable)
    assert planned.models_directory.path == str(models_directory)
