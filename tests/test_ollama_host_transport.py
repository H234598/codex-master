from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
import json
from pathlib import Path

import pytest

from codex_master.fleet_home_broker_transport import (
    BrokerOllamaInstancePayload,
    BrokerOperationRequest,
    BrokerOperationResponse,
)
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
from codex_master.agent_contracts import AgentPollV1


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


class FakeBroker:
    def __init__(self) -> None:
        self.calls = []

    def exchange(self, request, *, timeout_seconds, max_response_bytes):
        self.calls.append((request, timeout_seconds, max_response_bytes))
        status = {
            "plan": "planned",
            "apply": "running",
            "probe": "ready",
            "stop": "stopped",
        }[
            request.action
        ]
        digest = request.payload.plan_digest
        if request.action == "probe":
            payload = (
                '{"available_model_ids":["provider-llama-small"],'
                '"cgroup_member":true,"loopback_endpoint_reachable":true,'
                '"plan_digest":"'
                + digest
                + '","process_running":true,"ready":true,"reason_codes":[],'
                '"schema_version":1,"status":"ready"}'
            ).encode("ascii")
        else:
            payload = (
                '{"plan_digest":"'
                + digest
                + '","schema_version":1,"status":"'
                + status
                + '"}'
            ).encode("ascii")
        return BrokerOperationResponse(
            schema_version=1,
            operation_type=request.operation_type,
            action=request.action,
            host_ref=request.host_ref,
            request_id=request.request_id,
            status_code=200,
            redirected=False,
            payload=payload,
        )


class StaticBroker(FakeBroker):
    def __init__(self, payload: bytes):
        super().__init__()
        self.payload = payload

    def exchange(self, request, *, timeout_seconds, max_response_bytes):
        self.calls.append((request, timeout_seconds, max_response_bytes))
        return BrokerOperationResponse(
            1,
            request.operation_type,
            request.action,
            request.host_ref,
            request.request_id,
            200,
            False,
            self.payload,
        )


class ProbeBroker(FakeBroker):
    def __init__(self, probe_payload):
        super().__init__()
        self.probe_payload = probe_payload

    def exchange(self, request, *, timeout_seconds, max_response_bytes):
        if request.action != "probe":
            return super().exchange(
                request,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )
        self.calls.append((request, timeout_seconds, max_response_bytes))
        digest = request.payload.plan_digest
        payload = self.probe_payload.replace(b"PLAN_DIGEST", digest.encode("ascii"))
        return BrokerOperationResponse(
            1,
            request.operation_type,
            request.action,
            request.host_ref,
            request.request_id,
            200,
            False,
            payload,
        )


class _BrokerRemoteOllamaPort:
    """Legacy wire double behind the new remote-port boundary."""

    def __init__(self, broker: FakeBroker) -> None:
        self._broker = broker
        self._plans = {}

    def plan(self, request):
        self._plans[request.plan_digest] = request
        return self._call("plan", request, request.plan_digest)

    def apply(self, request):
        return self._call("apply", request, request.plan_digest)

    def probe(self, request):
        return self._call("probe", request, request.plan_digest)

    def stop(self, request):
        return self._call("stop", request, request.plan_digest)

    def _call(self, action, request, plan_digest):
        try:
            planned = self._plans[plan_digest]
            payload = BrokerOllamaInstancePayload(
                request.host_ref,
                request.instance_ref,
                planned.selected_model_refs,
                planned.allowed_cpus,
                planned.cpu_quota_percent,
                planned.cpu_weight,
                request.registry_generation,
                planned.runtime_generation,
                planned.fence,
                plan_digest,
                planned.idempotency_key,
            )
            response = self._broker.exchange(
                BrokerOperationRequest(
                    1,
                    "ollama.instance",
                    action,
                    request.host_ref,
                    "lease-" + "a" * 32,
                    "a" * 32,
                    payload,
                ),
                timeout_seconds=5,
                max_response_bytes=64 * 1024,
            )
        except Exception as error:
            raise OllamaHostError(str(error)) from None
        return json.loads(response.payload.decode("ascii"))


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


def lease(host_ref: str, *, fence: int = FENCE, expires_at: float = 200.0):
    return OllamaHostLease(
        host_ref=host_ref,
        lease_id=LEASE_ID,
        runtime_generation=RUNTIME_GENERATION,
        fence=fence,
        expires_at_monotonic=expires_at,
    )


def transport_for(
    placed: OllamaInstanceV1,
    *,
    current_lease: OllamaHostLease | None = None,
    now: float = 100.0,
):
    broker = FakeBroker()
    local = FakeLocalAdapter()
    transport = OllamaHostTransport(
        registry=RegistrySource(registry(placed)),
        leases=LeaseSource(current_lease or lease(placed.host_ref)),
        remote=_BrokerRemoteOllamaPort(broker),
        local=local,
        monotonic=lambda: now,
    )
    return transport, broker, local


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


def test_remote_plan_is_executed_on_selected_host_with_fixed_redacted_payload():
    placed = instance("worker-west")
    transport, broker, local = transport_for(placed)

    planned = transport.plan(placed, generation=MODEL_GENERATION)

    assert planned.host_ref == "worker-west"
    assert local.calls == []
    request = broker.calls[0][0]
    assert request.host_ref == "worker-west"
    assert request.operation_type == "ollama.instance"
    assert request.action == "plan"
    assert request.payload.host_ref == "worker-west"
    assert request.payload.instance_ref == "ollama-west"
    assert request.payload.model_generation == 8
    assert request.payload.runtime_generation == 13
    assert request.payload.fence == 3
    assert request.payload.idempotency_key == planned.idempotency_key
    assert planned.idempotency_key != planned.plan_digest
    serialized = repr(request.payload).encode("utf-8")
    for forbidden in (
        b"/private",
        b"provider-llama-small",
        b"executable",
        b"models_directory",
        b"argv",
        b"env",
        b"unit",
    ):
        assert forbidden not in serialized
    assert "/private" not in repr(planned)
    assert LEASE_ID not in repr(planned)


def test_plan_accepts_new_candidate_bound_to_current_model_catalog():
    placed = instance("worker-west")
    source = RegistrySource(OllamaRegistryV1(1, MODEL_GENERATION, (model(),), ()))
    broker = FakeBroker()
    transport = OllamaHostTransport(
        registry=source,
        leases=LeaseSource(lease("worker-west")),
        remote=_BrokerRemoteOllamaPort(broker),
        local=FakeLocalAdapter(),
        monotonic=lambda: 100.0,
    )

    planned = transport.plan(placed, generation=MODEL_GENERATION)

    assert planned.instance_ref == placed.ref
    assert broker.calls[0][0].action == "plan"


def test_stale_host_fence_blocks_before_runtime_action():
    placed = instance("worker-west")
    transport, broker, _local = transport_for(placed)
    planned = transport.plan(placed, generation=MODEL_GENERATION)
    broker.calls.clear()

    with pytest.raises(OllamaHostError, match="^control.plan_stale$"):
        transport.apply(planned, current_fence=FENCE + 1)

    assert broker.calls == []


def test_control_host_uses_local_task3_adapter_without_broker_call():
    placed = instance(CONTROL_HOST_REF)
    transport, broker, local = transport_for(placed)

    planned = transport.plan(placed, generation=MODEL_GENERATION)
    execution = transport.apply(planned, current_fence=FENCE)
    readiness = transport.probe(execution, current_fence=FENCE)

    assert [call[0] for call in local.calls] == ["plan", "apply", "probe"]
    assert local.calls[0][1].host_ref == "local"
    assert readiness.ready is True
    assert broker.calls == []


def test_successful_apply_retry_returns_same_execution_without_second_effect():
    placed = instance("worker-west")
    transport, broker, _local = transport_for(placed)
    planned = transport.plan(placed, generation=MODEL_GENERATION)

    first = transport.apply(planned, current_fence=FENCE)
    second = transport.apply(planned, current_fence=FENCE)

    assert second is first
    assert [call[0].action for call in broker.calls] == ["plan", "apply"]


@pytest.mark.parametrize("host_ref", (CONTROL_HOST_REF, "worker-west"))
def test_stop_targets_only_execution_created_by_transport(host_ref):
    placed = instance(host_ref)
    transport, broker, local = transport_for(placed)
    planned = transport.plan(placed, generation=MODEL_GENERATION)
    execution = transport.apply(planned, current_fence=FENCE)

    transport.stop(execution, current_fence=FENCE)
    transport.stop(execution, current_fence=FENCE)

    if host_ref == CONTROL_HOST_REF:
        assert [call[0] for call in local.calls] == ["plan", "apply", "stop"]
        assert broker.calls == []
    else:
        assert local.calls == []
        assert [call[0].action for call in broker.calls] == ["plan", "apply", "stop"]


def test_rotated_lease_gets_distinct_idempotency_binding_and_execution():
    placed = instance("worker-west")
    registry_source = RegistrySource(registry(placed))
    leases = LeaseSource(lease("worker-west"))
    broker = FakeBroker()
    transport = OllamaHostTransport(
        registry=registry_source,
        leases=leases,
        remote=_BrokerRemoteOllamaPort(broker),
        local=FakeLocalAdapter(),
        monotonic=lambda: 100.0,
    )
    first_plan = transport.plan(placed, generation=MODEL_GENERATION)
    first = transport.apply(first_plan, current_fence=FENCE)

    leases.value = replace(leases.value, lease_id="lease-" + "b" * 32)
    second_plan = transport.plan(placed, generation=MODEL_GENERATION)
    second = transport.apply(second_plan, current_fence=FENCE)

    assert second_plan.plan_digest != first_plan.plan_digest
    assert second_plan.idempotency_key != first_plan.idempotency_key
    assert second is not first
    assert [call[0].action for call in broker.calls] == [
        "plan",
        "apply",
        "plan",
        "apply",
    ]


def test_unknown_or_expired_lease_fails_before_any_host_call():
    placed = instance("worker-west")
    for current_lease in (None, lease("worker-west", expires_at=99.0)):
        source = LeaseSource(current_lease)
        broker = FakeBroker()
        transport = OllamaHostTransport(
            registry=RegistrySource(registry(placed)),
            leases=source,
            remote=_BrokerRemoteOllamaPort(broker),
            local=FakeLocalAdapter(),
            monotonic=lambda: 100.0,
        )

        expected = "resource.host_unreachable" if current_lease is None else "control.plan_stale"
        with pytest.raises(OllamaHostError, match=f"^{expected}$"):
            transport.plan(placed, generation=MODEL_GENERATION)
        assert broker.calls == []


def test_lease_type_confusion_is_rejected_before_host_call():
    class LeaseChild(OllamaHostLease):
        pass

    placed = instance("worker-west")
    broker = FakeBroker()
    transport = OllamaHostTransport(
        registry=RegistrySource(registry(placed)),
        leases=LeaseSource(
            LeaseChild(
                "worker-west",
                LEASE_ID,
                RUNTIME_GENERATION,
                FENCE,
                200.0,
            )
        ),
        remote=_BrokerRemoteOllamaPort(broker),
        local=FakeLocalAdapter(),
        monotonic=lambda: 100.0,
    )

    with pytest.raises(OllamaHostError, match="^resource.host_unreachable$"):
        transport.plan(placed, generation=MODEL_GENERATION)
    assert broker.calls == []


@pytest.mark.parametrize("unsafe", ("/private/model", "model\nsecret", "model ref"))
def test_remote_model_refs_cannot_smuggle_paths_or_control_text(unsafe):
    placed = replace(instance("worker-west"), selected_model_refs=(unsafe,))
    current = OllamaRegistryV1(1, MODEL_GENERATION, (model(unsafe),), (placed,))
    broker = FakeBroker()
    transport = OllamaHostTransport(
        registry=RegistrySource(current),
        leases=LeaseSource(lease("worker-west")),
        remote=_BrokerRemoteOllamaPort(broker),
        local=FakeLocalAdapter(),
        monotonic=lambda: 100.0,
    )

    with pytest.raises(OllamaHostError, match="^provider.operation_not_allowed$"):
        transport.plan(placed, generation=MODEL_GENERATION)
    assert broker.calls == []


def test_plan_expiry_and_runtime_generation_drift_block_apply_before_effect():
    placed = instance("worker-west")
    clock = [100.0]
    leases = LeaseSource(lease("worker-west"))
    broker = FakeBroker()
    transport = OllamaHostTransport(
        registry=RegistrySource(registry(placed)),
        leases=leases,
        remote=_BrokerRemoteOllamaPort(broker),
        local=FakeLocalAdapter(),
        monotonic=lambda: clock[0],
    )
    planned = transport.plan(placed, generation=MODEL_GENERATION)
    broker.calls.clear()

    leases.value = replace(leases.value, runtime_generation=RUNTIME_GENERATION + 1)
    with pytest.raises(OllamaHostError, match="^control.plan_stale$"):
        transport.apply(planned, current_fence=FENCE)
    assert broker.calls == []

    leases.value = lease("worker-west")
    clock[0] = 201.0
    with pytest.raises(OllamaHostError, match="^control.plan_stale$"):
        transport.apply(planned, current_fence=FENCE)
    assert broker.calls == []


def test_registry_generation_or_instance_binding_drift_blocks_apply():
    placed = instance("worker-west")
    registry_source = RegistrySource(registry(placed))
    broker = FakeBroker()
    transport = OllamaHostTransport(
        registry=registry_source,
        leases=LeaseSource(lease("worker-west")),
        remote=_BrokerRemoteOllamaPort(broker),
        local=FakeLocalAdapter(),
        monotonic=lambda: 100.0,
    )
    planned = transport.plan(placed, generation=MODEL_GENERATION)
    broker.calls.clear()

    registry_source.value = replace(
        registry_source.value,
        instances=(replace(placed, allowed_cpus="4-5"),),
    )
    with pytest.raises(OllamaHostError, match="^control.plan_stale$"):
        transport.apply(planned, current_fence=FENCE)
    assert broker.calls == []


def test_copied_plan_with_reused_seal_and_provenance_is_rejected():
    placed = instance("worker-west")
    transport, broker, _local = transport_for(placed)
    planned = transport.plan(placed, generation=MODEL_GENERATION)
    broker.calls.clear()

    copied = replace(planned)
    with pytest.raises(OllamaHostError, match="^control.plan_stale$"):
        transport.apply(copied, current_fence=FENCE)
    assert broker.calls == []


def test_malformed_remote_plan_response_is_code_only_and_fail_closed():
    placed = instance("worker-west")
    broker = StaticBroker(b'{"detail":"/private/worker/ollama"}')
    transport = OllamaHostTransport(
        registry=RegistrySource(registry(placed)),
        leases=LeaseSource(lease("worker-west")),
        remote=_BrokerRemoteOllamaPort(broker),
        local=FakeLocalAdapter(),
        monotonic=lambda: 100.0,
    )

    with pytest.raises(
        OllamaHostError, match="^resource.host_response_invalid$"
    ) as raised:
        transport.plan(placed, generation=MODEL_GENERATION)

    assert "/private" not in repr(raised.value)


def test_local_plan_provenance_is_not_copied_or_serialized():
    class NonCopyable:
        def __deepcopy__(self, memo):
            raise AssertionError("runtime provenance copied")

    placed = instance(CONTROL_HOST_REF)
    transport, _broker, local = transport_for(placed)
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


def test_remote_not_ready_probe_accepts_bounded_ollama_model_ids():
    placed = instance("worker-west")
    payload = (
        b'{"available_model_ids":["llama3.2:3b"],"cgroup_member":true,'
        b'"loopback_endpoint_reachable":true,"plan_digest":"PLAN_DIGEST",'
        b'"process_running":true,"ready":false,'
        b'"reason_codes":["provider.model_unavailable"],'
        b'"schema_version":1,"status":"not_ready"}'
    )
    broker = ProbeBroker(payload)
    transport = OllamaHostTransport(
        registry=RegistrySource(registry(placed)),
        leases=LeaseSource(lease("worker-west")),
        remote=_BrokerRemoteOllamaPort(broker),
        local=FakeLocalAdapter(),
        monotonic=lambda: 100.0,
    )

    planned = transport.plan(placed, generation=MODEL_GENERATION)
    execution = transport.apply(planned, current_fence=FENCE)
    readiness = transport.probe(execution, current_fence=FENCE)

    assert readiness.ready is False
    assert readiness.reason_codes == ("provider.model_unavailable",)
    assert readiness.available_model_ids == ("llama3.2:3b",)


@pytest.mark.parametrize(
    "models,reasons",
    ((["llama3.2:3b"], []), (["/private/worker/model"], ["provider.model_unavailable"])),
)
def test_remote_not_ready_probe_rejects_missing_reason_or_absolute_path(
    models, reasons
):
    placed = instance("worker-west")
    model_json = "[" + ",".join(f'"{value}"' for value in models) + "]"
    reason_json = "[" + ",".join(f'"{value}"' for value in reasons) + "]"
    payload = (
        '{"available_model_ids":'
        + model_json
        + ',"cgroup_member":true,"loopback_endpoint_reachable":true,'
        '"plan_digest":"PLAN_DIGEST","process_running":true,"ready":false,'
        '"reason_codes":'
        + reason_json
        + ',"schema_version":1,"status":"not_ready"}'
    ).encode("ascii")
    broker = ProbeBroker(payload)
    transport = OllamaHostTransport(
        registry=RegistrySource(registry(placed)),
        leases=LeaseSource(lease("worker-west")),
        remote=_BrokerRemoteOllamaPort(broker),
        local=FakeLocalAdapter(),
        monotonic=lambda: 100.0,
    )
    planned = transport.plan(placed, generation=MODEL_GENERATION)
    execution = transport.apply(planned, current_fence=FENCE)

    with pytest.raises(OllamaHostError, match="^resource.host_response_invalid$"):
        transport.probe(execution, current_fence=FENCE)


def test_remote_ready_probe_requires_model_evidence():
    placed = instance("worker-west")
    payload = (
        b'{"available_model_ids":[],"cgroup_member":true,'
        b'"loopback_endpoint_reachable":true,"plan_digest":"PLAN_DIGEST",'
        b'"process_running":true,"ready":true,"reason_codes":[],'
        b'"schema_version":1,"status":"ready"}'
    )
    broker = ProbeBroker(payload)
    transport = OllamaHostTransport(
        registry=RegistrySource(registry(placed)),
        leases=LeaseSource(lease("worker-west")),
        remote=_BrokerRemoteOllamaPort(broker),
        local=FakeLocalAdapter(),
        monotonic=lambda: 100.0,
    )
    planned = transport.plan(placed, generation=MODEL_GENERATION)
    execution = transport.apply(planned, current_fence=FENCE)

    with pytest.raises(OllamaHostError, match="^resource.host_response_invalid$"):
        transport.probe(execution, current_fence=FENCE)
