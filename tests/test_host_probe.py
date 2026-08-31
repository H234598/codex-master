from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
import json
import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from codex_master.admin_hosts import (
    AgentPrincipalV1 as RegistryPrincipalV1,
    HostRegistry,
    HostRegistryError,
)
from codex_master.admin_operations import AdminOperationError, AdminOperationStore
from codex_master.agent_contracts import (
    AgentLeaseV1,
    AgentPollV1,
    AgentReceiptV1,
    AgentResultV1,
    serialize_agent_result,
)
from codex_master.agent_operations import (
    AgentAttemptExhaustionV1,
    AgentOperationDeadlineExpiryV1,
    AgentOperationError,
    AgentOperationRequestV1,
    AgentOperationStore,
    AgentPrincipalV1 as OperationPrincipalV1,
)
from codex_master.host_probe import (
    HostProbeError,
    HostProbeEvidenceV1,
    HostProbeRouter,
    LocalHostProbeAdapter,
    LocalHostProbeCollector,
    RemoteHostProbeAdapter,
    RemoteHostProbeCompletionOwner,
    _operation_key,
)


class Kernel:
    def __init__(self, *, cpu_count: object = 8, memory_bytes: object = 16 * 1024**3) -> None:
        self.cpu_count = cpu_count
        self.memory_bytes = memory_bytes

    def uname(self) -> tuple[str, str]:
        return ("Linux", "x86_64")

    def cgroup_v2(self) -> bool:
        return True

    def systemd(self) -> bool:
        return True

    def load(self) -> float:
        return 0.5

    def pressure(self) -> float:
        return 0.0

    def ollama_available(self) -> bool:
        return False


NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
CAPABILITIES_DIGEST = "sha256:" + "c" * 64


def _registry_evidence(*, observed_at: str = "2026-08-30T11:00:00Z") -> dict[str, object]:
    return {
        "label": "Worker One",
        "role": "execution",
        "transport_binding": {"kind": "ssh", "binding_ref": "worker-one-ssh"},
        "capabilities": ["codex.execute", "resource.probe"],
        "reachability": {"state": "reachable", "latency_ms": 12},
        "resource_evidence": {"cpu_threads": 4, "memory_bytes": 8 * 1024**3},
        "observed_at": observed_at,
        "source": "host-agent",
        "binding_state": {"opaque": "binding-one"},
    }


def _evidence(*, observed_at: str = "2026-08-30T12:00:00Z") -> HostProbeEvidenceV1:
    return HostProbeEvidenceV1(
        "linux",
        "x86_64",
        8,
        "8-31-gib",
        True,
        True,
        "idle",
        "none",
        False,
        observed_at,
    )


def _result_digest(result: AgentResultV1) -> str:
    encoded = json.dumps(
        serialize_agent_result(result),
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _receipt(
    lease: AgentLeaseV1,
    *,
    state: str = "succeeded",
    payload: dict[str, object] | None = None,
) -> AgentReceiptV1:
    result = AgentResultV1(
        "host.probe",
        "collect",
        _evidence().public() if payload is None else payload,
    )
    return AgentReceiptV1(
        lease.operation_id,
        lease.lease_id,
        lease.lease_epoch,
        lease.attempt,
        lease.plan_digest,
        lease.arguments_digest,
        cast(str, state),  # type: ignore[arg-type]
        ("host.probe_collected",) if state == "succeeded" else ("host.probe_unknown",),
        _result_digest(result),
        result,
    )


def _registry_document(tmp_path: Path) -> Path:
    return tmp_path / "admin-hosts" / "hosts.json"


def _remote_scenario(
    tmp_path: Path,
    *,
    clock: Callable[[], datetime] | None = None,
) -> tuple[
    RemoteHostProbeCompletionOwner,
    AdminOperationStore,
    AgentOperationStore,
    HostRegistry,
    RegistryPrincipalV1,
    AgentLeaseV1,
    str,
]:
    actual_clock = clock or (lambda: NOW)
    registry = HostRegistry.for_test(tmp_path)
    registry.record_probe("worker-one", generation=4, evidence=_registry_evidence())
    operations = AdminOperationStore.for_test(tmp_path, clock=actual_clock)
    agent_operations = AgentOperationStore.for_test(tmp_path, clock=actual_clock)
    adapter = RemoteHostProbeAdapter(
        operation_store=operations,
        agent_operations=agent_operations,
        host_registry=registry,
        clock=actual_clock,
    )
    planned = adapter.probe(
        "worker-one", expected_generation=4, idempotency_key="probe-one"
    )
    document_generation = registry.document_generation()
    operation_principal = OperationPrincipalV1("worker-one", document_generation)
    lease = agent_operations.poll(
        operation_principal,
        AgentPollV1(document_generation, 1, CAPABILITIES_DIGEST, 0),
    )
    assert isinstance(lease, AgentLeaseV1)
    operation_id = lease.arguments["admin_operation_id"]
    assert type(operation_id) is str
    assert operation_id == planned.id
    return (
        RemoteHostProbeCompletionOwner(
            operation_store=operations,
            agent_operations=agent_operations,
            host_registry=registry,
        ),
        operations,
        agent_operations,
        registry,
        RegistryPrincipalV1("worker-one", document_generation, 1),
        lease,
        operation_id,
    )


class _Collector:
    def __init__(self, result: HostProbeEvidenceV1 | BaseException) -> None:
        self.result = result

    def collect(self) -> HostProbeEvidenceV1:
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


def test_local_probe_collects_only_bounded_normalized_evidence() -> None:
    evidence = LocalHostProbeCollector(lambda: datetime(2026, 8, 30, tzinfo=UTC)).collect(Kernel())

    assert set(evidence.public()) == {
        "kernel_class", "architecture_class", "cpu_count", "memory_class",
        "cgroup_v2", "systemd", "load_class", "pressure_class",
        "ollama_capability", "observed_at", "agent_generation", "evidence_digest",
    }
    assert "/" not in json.dumps(evidence.public())
    assert evidence.public()["cpu_count"] == 8
    assert evidence.public()["memory_class"] == "8-31-gib"


@pytest.mark.parametrize("field", ("cpu_count", "memory_bytes"))
def test_local_probe_rejects_boolean_resource_values(field: str) -> None:
    values = {field: True}

    with pytest.raises(HostProbeError, match="host.probe_failed"):
        LocalHostProbeCollector().collect(Kernel(**values))


def test_local_probe_maps_collector_failure_to_stable_code() -> None:
    class Broken(Kernel):
        def uname(self) -> tuple[str, str]:
            raise OSError

    with pytest.raises(HostProbeError, match="host.probe_failed"):
        LocalHostProbeCollector().collect(Broken())


def test_remote_evidence_uses_the_exact_same_public_dto_validation() -> None:
    local = LocalHostProbeCollector(lambda: datetime(2026, 8, 30, tzinfo=UTC)).collect(Kernel())

    assert HostProbeEvidenceV1.from_public(local.public()).public() == local.public()
    tampered = local.public()
    tampered["evidence_digest"] = "sha256:" + "0" * 64
    with pytest.raises(HostProbeError, match="host.probe_failed"):
        HostProbeEvidenceV1.from_public(tampered)


def test_host_bound_internal_idempotency_never_aliases_hosts() -> None:
    assert _operation_key("worker-one", "client-key") != _operation_key("worker-two", "client-key")


def test_probe_evidence_digest_is_stable_for_completion_retry() -> None:
    evidence = LocalHostProbeCollector(
        lambda: datetime(2026, 8, 30, tzinfo=UTC)
    ).collect(Kernel())

    assert HostProbeEvidenceV1.from_public(evidence.public()).public() == evidence.public()


@pytest.mark.parametrize(
    "observed_at",
    ("not-a-utc-timestamp!", "2026-08-30T12:00:00+00:00", "2026-02-30T12:00:00Z"),
)
def test_probe_evidence_rejects_noncanonical_observed_at(observed_at: str) -> None:
    with pytest.raises(HostProbeError, match="host.probe_failed"):
        HostProbeEvidenceV1(
            "linux", "x86_64", 8, "8-31-gib", True, True, "idle", "none",
            False, observed_at,
        )


def test_local_adapter_records_fresh_probe_and_completes_real_operation(
    tmp_path: Path,
) -> None:
    registry = HostRegistry.for_test(tmp_path)
    original = registry.record_probe(
        "worker-one", generation=4, evidence=_registry_evidence()
    )
    operations = AdminOperationStore.for_test(tmp_path, clock=lambda: NOW)
    adapter = LocalHostProbeAdapter(
        operation_store=operations,
        host_registry=registry,
        collector=cast(LocalHostProbeCollector, _Collector(_evidence())),
    )

    completed = adapter.probe(
        "worker-one", expected_generation=4, idempotency_key="local-one"
    )

    assert completed.state == "succeeded"
    assert completed.resulting_generation == 5
    assert operations.get(completed.id) == completed
    refreshed = registry.get("worker-one")
    assert refreshed.generation == 5
    assert refreshed.resource_evidence == {
        "cpu_threads": 8,
        "memory_bytes": 8 * 1024**3,
    }
    assert (refreshed.label, refreshed.role, refreshed.transport_binding) == (
        original.label,
        original.role,
        original.transport_binding,
    )


def test_local_adapter_collector_failure_is_terminal_without_registry_mutation(
    tmp_path: Path,
) -> None:
    registry = HostRegistry.for_test(tmp_path)
    registry.record_probe("worker-one", generation=4, evidence=_registry_evidence())
    document = _registry_document(tmp_path)
    before = document.read_bytes()
    operations = AdminOperationStore.for_test(tmp_path, clock=lambda: NOW)
    adapter = LocalHostProbeAdapter(
        operation_store=operations,
        host_registry=registry,
        collector=cast(LocalHostProbeCollector, _Collector(OSError("private detail"))),
    )

    failed = adapter.probe(
        "worker-one", expected_generation=4, idempotency_key="local-failure"
    )

    assert failed.state == "failed"
    assert failed.reason_codes == ("host.probe_failed",)
    assert document.read_bytes() == before


def test_remote_adapter_queues_exact_target_bound_collect_operation(
    tmp_path: Path,
) -> None:
    registry = HostRegistry.for_test(tmp_path)
    registry.record_probe("worker-one", generation=4, evidence=_registry_evidence())
    operations = AdminOperationStore.for_test(tmp_path, clock=lambda: NOW)
    agent_operations = AgentOperationStore.for_test(tmp_path, clock=lambda: NOW)
    adapter = RemoteHostProbeAdapter(
        operation_store=operations,
        agent_operations=agent_operations,
        host_registry=registry,
        clock=lambda: NOW,
    )

    planned = adapter.probe(
        "worker-one", expected_generation=4, idempotency_key="remote-one"
    )
    principal = OperationPrincipalV1("worker-one", 4)
    lease = agent_operations.poll(
        principal, AgentPollV1(4, 1, CAPABILITIES_DIGEST, 0)
    )

    assert planned.state == "planned"
    assert isinstance(lease, AgentLeaseV1)
    assert (lease.kind, lease.action, lease.host_ref) == (
        "host.probe",
        "collect",
        "worker-one",
    )
    assert lease.registry_generation == 4
    assert lease.arguments == {
        "admin_operation_id": planned.id,
        "probe_schema": 1,
    }
    context = agent_operations.context(lease.operation_id)
    assert context["target_host_ref"] == "worker-one"
    assert operations.get(planned.id).state == "planned"


def test_router_uses_real_local_and_remote_adapters_without_crossing_paths(
    tmp_path: Path,
) -> None:
    registry = HostRegistry.for_test(tmp_path)
    registry.record_probe(
        "control-host",
        generation=4,
        evidence=_registry_evidence(),
    )
    registry.record_probe(
        "worker-one",
        generation=4,
        evidence=_registry_evidence(),
    )
    operations = AdminOperationStore.for_test(tmp_path, clock=lambda: NOW)
    agent_operations = AgentOperationStore.for_test(tmp_path, clock=lambda: NOW)
    router = HostProbeRouter(
        local_host_ref="control-host",
        local=LocalHostProbeAdapter(
            operation_store=operations,
            host_registry=registry,
            collector=_Collector(_evidence()),
        ),
        remote=RemoteHostProbeAdapter(
            operation_store=operations,
            agent_operations=agent_operations,
            host_registry=registry,
            clock=lambda: NOW,
        ),
    )

    local = router.probe(
        "control-host",
        expected_generation=4,
        idempotency_key="router-local",
    )
    remote = router.probe(
        "worker-one",
        expected_generation=4,
        idempotency_key="router-remote",
    )

    assert local.state == "succeeded"
    assert remote.state == "planned"
    operation_document = json.loads(
        (tmp_path / "agent-operations" / "operations.json").read_text(
            encoding="utf-8"
        )
    )
    assert len(operation_document["operations"]) == 1
    assert operation_document["operations"][0]["target_host_ref"] == "worker-one"


def test_remote_probe_separates_document_and_host_generation_without_wire_drift(
    tmp_path: Path,
) -> None:
    registry = HostRegistry.for_test(tmp_path)
    registry.record_probe("worker-one", generation=1, evidence=_registry_evidence())
    other = _registry_evidence()
    other["label"] = "Worker Two"
    other["transport_binding"] = {
        "kind": "ssh",
        "binding_ref": "worker-two-ssh",
    }
    other["binding_state"] = {"opaque": "binding-two"}
    registry.record_probe("worker-two", generation=7, evidence=other)
    operations = AdminOperationStore.for_test(tmp_path, clock=lambda: NOW)
    agent_operations = AgentOperationStore.for_test(tmp_path, clock=lambda: NOW)
    adapter = RemoteHostProbeAdapter(
        operation_store=operations,
        agent_operations=agent_operations,
        host_registry=registry,
        clock=lambda: NOW,
    )

    planned = adapter.probe(
        "worker-one", expected_generation=1, idempotency_key="divergent-generation"
    )
    document_generation = registry.document_generation()
    principal = OperationPrincipalV1("worker-one", document_generation)
    lease = agent_operations.poll(
        principal,
        AgentPollV1(document_generation, 1, CAPABILITIES_DIGEST, 0),
    )
    assert isinstance(lease, AgentLeaseV1)
    assert lease.registry_generation == 7
    assert lease.arguments == {
        "admin_operation_id": planned.id,
        "probe_schema": 1,
    }

    completed = RemoteHostProbeCompletionOwner(
        operation_store=operations,
        agent_operations=agent_operations,
        host_registry=registry,
    ).complete(
        RegistryPrincipalV1("worker-one", document_generation, 1),
        _receipt(lease),
    )

    assert completed.state == "succeeded"
    assert operations.get(planned.id).resulting_generation == 2
    assert registry.get("worker-one").generation == 2
    assert registry.document_generation() == 8


def test_remote_completion_records_valid_dto_then_terminalizes_both_operations(
    tmp_path: Path,
) -> None:
    owner, operations, agent_operations, registry, principal, lease, operation_id = (
        _remote_scenario(tmp_path)
    )

    completed = owner.complete(principal, _receipt(lease))

    assert completed == agent_operations.get(lease.operation_id)
    assert completed.state == "succeeded"
    assert operations.get(operation_id).state == "succeeded"
    assert operations.get(operation_id).resulting_generation == 5
    assert registry.get("worker-one").generation == 5


def test_remote_completion_invalid_dto_terminalizes_without_registry_mutation(
    tmp_path: Path,
) -> None:
    owner, operations, agent_operations, _registry, principal, lease, operation_id = (
        _remote_scenario(tmp_path)
    )
    document = _registry_document(tmp_path)
    before = document.read_bytes()

    completed = owner.complete(
        principal, _receipt(lease, payload={"kernel_class": "linux"})
    )

    assert completed.state == "succeeded"
    assert agent_operations.get(lease.operation_id).state == "succeeded"
    assert operations.get(operation_id).state == "failed"
    assert document.read_bytes() == before


def test_remote_completion_stale_generation_terminalizes_without_registry_mutation(
    tmp_path: Path,
) -> None:
    owner, operations, agent_operations, registry, principal, lease, operation_id = (
        _remote_scenario(tmp_path)
    )
    changed = _registry_evidence(observed_at="2026-08-30T11:30:00Z")
    changed["resource_evidence"] = {
        "cpu_threads": 6,
        "memory_bytes": 12 * 1024**3,
    }
    registry.record_probe("worker-one", generation=5, evidence=changed)
    document = _registry_document(tmp_path)
    before = document.read_bytes()

    completed = owner.complete(principal, _receipt(lease))

    assert completed.state == "succeeded"
    assert agent_operations.get(lease.operation_id).state == "succeeded"
    assert operations.get(operation_id).state == "failed"
    assert document.read_bytes() == before


def test_remote_completion_running_stale_generation_cannot_overwrite_new_probe(
    tmp_path: Path,
) -> None:
    owner, operations, agent_operations, registry, principal, lease, operation_id = (
        _remote_scenario(tmp_path)
    )
    operations.begin(operation_id, current_generation=4)
    changed = _registry_evidence(observed_at="2026-08-30T11:30:00Z")
    changed["resource_evidence"] = {
        "cpu_threads": 6,
        "memory_bytes": 12 * 1024**3,
    }
    registry.record_probe("worker-one", generation=5, evidence=changed)
    document = _registry_document(tmp_path)
    before = document.read_bytes()

    completed = owner.complete(principal, _receipt(lease))

    assert completed.state == "succeeded"
    assert agent_operations.get(lease.operation_id).state == "succeeded"
    assert operations.get(operation_id).state == "failed"
    assert document.read_bytes() == before


def test_remote_completion_cross_host_rejection_cannot_terminalize_target_work(
    tmp_path: Path,
) -> None:
    owner, operations, agent_operations, _registry, _principal, lease, operation_id = (
        _remote_scenario(tmp_path)
    )
    document = _registry_document(tmp_path)
    before = document.read_bytes()

    with pytest.raises(AgentOperationError, match="host.identity_mismatch"):
        owner.complete(RegistryPrincipalV1("worker-two", 4, 1), _receipt(lease))

    assert operations.get(operation_id).state == "planned"
    assert agent_operations.get(lease.operation_id).state == "leased"
    assert document.read_bytes() == before


@pytest.mark.parametrize("receipt_state", ("failed", "unknown"))
def test_remote_completion_non_success_is_terminal_without_registry_mutation(
    tmp_path: Path, receipt_state: str
) -> None:
    owner, operations, agent_operations, _registry, principal, lease, operation_id = (
        _remote_scenario(tmp_path)
    )
    document = _registry_document(tmp_path)
    before = document.read_bytes()

    completed = owner.complete(principal, _receipt(lease, state=receipt_state))

    assert completed.state == receipt_state
    assert agent_operations.get(lease.operation_id).state == receipt_state
    failed = operations.get(operation_id)
    assert failed.state == "failed"
    assert failed.reason_codes == ("host.probe_unknown",)
    assert document.read_bytes() == before


@pytest.mark.parametrize("receipt_state", ("succeeded", "failed", "unknown"))
def test_registry_get_unavailability_does_not_consume_probe_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    receipt_state: str,
) -> None:
    owner, operations, agent_operations, registry, principal, lease, operation_id = (
        _remote_scenario(tmp_path)
    )
    document = _registry_document(tmp_path)
    before = document.read_bytes()
    original_get = registry.get
    attempts = 0

    def unavailable_once(ref: str):  # type: ignore[no-untyped-def]
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise HostRegistryError("control.host_store_unavailable")
        return original_get(ref)

    monkeypatch.setattr(registry, "get", unavailable_once)
    receipt = _receipt(lease, state=receipt_state)

    with pytest.raises(HostRegistryError, match="control.host_store_unavailable"):
        owner.complete(principal, receipt)

    assert operations.get(operation_id).state == "planned"
    assert agent_operations.get(lease.operation_id).state == "leased"
    assert document.read_bytes() == before

    completed = owner.complete(principal, receipt)

    assert completed.state == receipt_state
    assert agent_operations.get(lease.operation_id).state == receipt_state
    if receipt_state == "succeeded":
        assert operations.get(operation_id).state == "succeeded"
        assert registry.get("worker-one").generation == 5
    else:
        assert operations.get(operation_id).state == "failed"
        assert document.read_bytes() == before


def test_registry_get_definitive_missing_host_terminalizes_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner, operations, agent_operations, registry, principal, lease, operation_id = (
        _remote_scenario(tmp_path)
    )
    document = _registry_document(tmp_path)
    before = document.read_bytes()

    def missing(_ref: str):  # type: ignore[no-untyped-def]
        raise HostRegistryError("control.host_not_found")

    monkeypatch.setattr(registry, "get", missing)
    completed = owner.complete(principal, _receipt(lease))

    assert completed.state == "succeeded"
    assert operations.get(operation_id).state == "failed"
    assert agent_operations.get(lease.operation_id).state == "succeeded"
    assert document.read_bytes() == before


def test_generation_exhaustion_terminalizes_without_registry_mutation(
    tmp_path: Path,
) -> None:
    maximum = 2**63 - 1
    registry = HostRegistry.for_test(tmp_path)
    registry.record_probe(
        "worker-one", generation=maximum, evidence=_registry_evidence()
    )
    operations = AdminOperationStore.for_test(tmp_path, clock=lambda: NOW)
    agent_operations = AgentOperationStore.for_test(tmp_path, clock=lambda: NOW)
    planned = RemoteHostProbeAdapter(
        operation_store=operations,
        agent_operations=agent_operations,
        host_registry=registry,
        clock=lambda: NOW,
    ).probe(
        "worker-one", expected_generation=maximum, idempotency_key="generation-max"
    )
    lease = agent_operations.poll(
        OperationPrincipalV1("worker-one", maximum),
        AgentPollV1(maximum, 1, CAPABILITIES_DIGEST, 0),
    )
    assert isinstance(lease, AgentLeaseV1)
    document = _registry_document(tmp_path)
    before = document.read_bytes()
    admin_states_at_agent_completion: list[str] = []
    original_complete = agent_operations.complete

    def ordered_complete(principal, receipt):  # type: ignore[no-untyped-def]
        admin_states_at_agent_completion.append(operations.get(planned.id).state)
        return original_complete(principal, receipt)

    agent_operations.complete = ordered_complete  # type: ignore[method-assign]
    completed = RemoteHostProbeCompletionOwner(
        operation_store=operations,
        agent_operations=agent_operations,
        host_registry=registry,
    ).complete(
        RegistryPrincipalV1("worker-one", maximum, 1),
        _receipt(lease),
    )

    assert completed.state == "succeeded"
    assert operations.get(planned.id).state == "failed"
    assert agent_operations.get(lease.operation_id).state == "succeeded"
    assert admin_states_at_agent_completion == ["failed"]
    assert document.read_bytes() == before


def test_remote_completion_duplicate_is_idempotent_and_conflict_is_rejected(
    tmp_path: Path,
) -> None:
    owner, operations, agent_operations, _registry, principal, lease, operation_id = (
        _remote_scenario(tmp_path)
    )
    receipt = _receipt(lease)
    first = owner.complete(principal, receipt)
    document = _registry_document(tmp_path)
    after_first = document.read_bytes()

    assert owner.complete(principal, receipt) == first
    assert document.read_bytes() == after_first
    with pytest.raises(AgentOperationError, match="host.completion_conflict"):
        owner.complete(principal, _receipt(lease, state="failed"))
    assert operations.get(operation_id).state == "succeeded"
    assert agent_operations.get(lease.operation_id) == first
    assert document.read_bytes() == after_first


@pytest.mark.parametrize("receipt_state", ("succeeded", "failed", "unknown"))
def test_agent_terminal_ack_failure_retries_after_owner_reconstruction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    receipt_state: str,
) -> None:
    owner, operations, agent_operations, _registry, principal, lease, operation_id = (
        _remote_scenario(tmp_path)
    )
    receipt = _receipt(lease, state=receipt_state)
    original_ack = operations.acknowledge_host_probe_agent
    attempts = 0

    def fail_ack_once(*args: object, **kwargs: object) -> object:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise AdminOperationError("control.operation_store_unavailable")
        return original_ack(*args, **kwargs)

    monkeypatch.setattr(
        operations,
        "acknowledge_host_probe_agent",
        fail_ack_once,
    )

    with pytest.raises(AdminOperationError, match="control.operation_store_unavailable"):
        owner.complete(principal, receipt)

    assert operations.get(operation_id).state in {"succeeded", "failed"}
    assert agent_operations.get(lease.operation_id).state == receipt_state

    operations = AdminOperationStore.for_test(tmp_path, clock=lambda: NOW)
    agent_operations = AgentOperationStore.for_test(tmp_path, clock=lambda: NOW)
    completed = RemoteHostProbeCompletionOwner(
        operation_store=operations,
        agent_operations=agent_operations,
        host_registry=HostRegistry.for_test(tmp_path),
    ).complete(principal, receipt)

    assert completed.state == receipt_state
    lifecycle = json.loads(
        (
            tmp_path / "admin-operations" / "host-probe-lifecycle.json"
        ).read_text(encoding="utf-8")
    )
    assert lifecycle["owners"][0]["acknowledged"] is True


@pytest.mark.parametrize(
    ("phase", "first_admin_state"),
    (
        ("begin", "planned"),
        ("record_step", "running"),
        ("finish", "running"),
        ("agent_complete", "failed"),
    ),
)
def test_non_success_completion_failure_retries_converge_without_registry_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
    first_admin_state: str,
) -> None:
    owner, operations, agent_operations, _registry, principal, lease, operation_id = (
        _remote_scenario(tmp_path)
    )
    document = _registry_document(tmp_path)
    before = document.read_bytes()
    target = agent_operations if phase == "agent_complete" else operations
    method_name = "complete" if phase == "agent_complete" else phase
    original = getattr(target, method_name)
    attempts = 0

    def fail_once(*args: object, **kwargs: object) -> object:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            if phase == "agent_complete":
                raise AgentOperationError("host.operation_store_unavailable")
            raise AdminOperationError("control.operation_store_unavailable")
        return original(*args, **kwargs)

    monkeypatch.setattr(target, method_name, fail_once)

    with pytest.raises((AdminOperationError, AgentOperationError)):
        owner.complete(principal, _receipt(lease, state="unknown"))

    assert operations.get(operation_id).state == first_admin_state
    assert agent_operations.get(lease.operation_id).state == "leased"
    assert document.read_bytes() == before

    completed = owner.complete(principal, _receipt(lease, state="unknown"))

    assert completed.state == "unknown"
    assert operations.get(operation_id).state == "failed"
    assert agent_operations.get(lease.operation_id).state == "unknown"
    assert document.read_bytes() == before


@pytest.mark.parametrize(
    "phase", ("registry", "begin", "record_step", "finish", "agent_complete")
)
def test_success_completion_store_failures_retry_without_double_registry_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
) -> None:
    owner, operations, agent_operations, registry, principal, lease, operation_id = (
        _remote_scenario(tmp_path)
    )
    before = _registry_document(tmp_path).read_bytes()
    writes = 0
    original_write = registry._write_locked

    def counted_write(*args: object, **kwargs: object) -> object:
        nonlocal writes
        writes += 1
        return original_write(*args, **kwargs)

    monkeypatch.setattr(registry, "_write_locked", counted_write)
    if phase == "registry":
        target = registry
        method_name = "record_active_probe"
    elif phase == "agent_complete":
        target = agent_operations
        method_name = "complete"
    else:
        target = operations
        method_name = phase
    original = getattr(target, method_name)
    attempts = 0

    def fail_once(*args: object, **kwargs: object) -> object:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            if phase == "registry":
                raise HostRegistryError("control.host_store_unavailable")
            if phase == "agent_complete":
                raise AgentOperationError("host.operation_store_unavailable")
            raise AdminOperationError("control.operation_store_unavailable")
        return original(*args, **kwargs)

    monkeypatch.setattr(target, method_name, fail_once)

    with pytest.raises((HostRegistryError, AdminOperationError, AgentOperationError)):
        owner.complete(principal, _receipt(lease))

    first_bytes = _registry_document(tmp_path).read_bytes()
    expected_writes = 1 if phase in {"record_step", "finish", "agent_complete"} else 0
    assert writes == expected_writes
    assert agent_operations.get(lease.operation_id).state == "leased"
    if expected_writes == 0:
        assert first_bytes == before

    completed = owner.complete(principal, _receipt(lease))

    assert completed.state == "succeeded"
    assert operations.get(operation_id).state == "succeeded"
    assert agent_operations.get(lease.operation_id).state == "succeeded"
    assert registry.get("worker-one").generation == 5
    assert writes == 1
    if expected_writes:
        assert _registry_document(tmp_path).read_bytes() == first_bytes


@pytest.mark.parametrize(
    ("receipt_state", "boundary"),
    (
        ("succeeded", "begin"),
        ("succeeded", "resume"),
        ("succeeded", "registry"),
        ("succeeded", "record_step"),
        ("succeeded", "finish"),
        ("succeeded", "agent_complete"),
        ("failed", "begin"),
        ("failed", "resume"),
        ("failed", "record_step"),
        ("failed", "finish"),
        ("failed", "agent_complete"),
        ("unknown", "begin"),
        ("unknown", "resume"),
        ("unknown", "record_step"),
        ("unknown", "finish"),
        ("unknown", "agent_complete"),
    ),
)
def test_reconstructed_probe_owners_converge_after_each_persisted_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    receipt_state: str,
    boundary: str,
) -> None:
    class DeadOwnerProbe:
        def current(self) -> tuple[str, int, int]:
            return ("11111111-1111-1111-1111-111111111111", 4321, 101)

        def is_alive(self, _owner: tuple[str, int, int]) -> bool:
            return False

    owner_probe = DeadOwnerProbe()
    registry = HostRegistry.for_test(tmp_path)
    registry.record_probe("worker-one", generation=4, evidence=_registry_evidence())
    operations = AdminOperationStore.for_test(
        tmp_path, clock=lambda: NOW, owner_probe=owner_probe
    )
    agent_operations = AgentOperationStore.for_test(tmp_path, clock=lambda: NOW)
    planned = RemoteHostProbeAdapter(
        operation_store=operations,
        agent_operations=agent_operations,
        host_registry=registry,
        clock=lambda: NOW,
    ).probe("worker-one", expected_generation=4, idempotency_key="restart-probe")
    document_generation = registry.document_generation()
    lease = agent_operations.poll(
        OperationPrincipalV1("worker-one", document_generation),
        AgentPollV1(document_generation, 1, CAPABILITIES_DIGEST, 0),
    )
    assert isinstance(lease, AgentLeaseV1)
    principal = RegistryPrincipalV1("worker-one", document_generation, 1)
    receipt = _receipt(lease, state=receipt_state)
    operations = AdminOperationStore.for_test(
        tmp_path, clock=lambda: NOW, owner_probe=owner_probe
    )
    agent_operations = AgentOperationStore.for_test(tmp_path, clock=lambda: NOW)
    registry = HostRegistry.for_test(tmp_path)
    owner = RemoteHostProbeCompletionOwner(
        operation_store=operations,
        agent_operations=agent_operations,
        host_registry=registry,
    )
    ordered_states: list[str] = []

    if boundary == "resume":
        operations.begin(planned.id, current_generation=4)
        operations = AdminOperationStore.for_test(
            tmp_path, clock=lambda: NOW, owner_probe=owner_probe
        )
        agent_operations = AgentOperationStore.for_test(tmp_path, clock=lambda: NOW)
        registry = HostRegistry.for_test(tmp_path)
        owner = RemoteHostProbeCompletionOwner(
            operation_store=operations,
            agent_operations=agent_operations,
            host_registry=registry,
        )
        target = operations
        method_name = "resume_host_probe"
    elif boundary == "registry":
        target = registry
        method_name = "record_active_probe"
    elif boundary == "agent_complete":
        target = agent_operations
        method_name = "complete"
    else:
        target = operations
        method_name = boundary
    original = getattr(target, method_name)

    def crash_after_persist(*args: object, **kwargs: object) -> object:
        if boundary == "agent_complete":
            ordered_states.append(operations.get(planned.id).state)
        original(*args, **kwargs)
        raise RuntimeError("simulated process exit after durable boundary")

    monkeypatch.setattr(target, method_name, crash_after_persist)

    with pytest.raises(RuntimeError, match="simulated process exit"):
        owner.complete(principal, receipt)

    operations = AdminOperationStore.for_test(
        tmp_path, clock=lambda: NOW, owner_probe=owner_probe
    )
    agent_operations = AgentOperationStore.for_test(tmp_path, clock=lambda: NOW)
    registry = HostRegistry.for_test(tmp_path)
    owner = RemoteHostProbeCompletionOwner(
        operation_store=operations,
        agent_operations=agent_operations,
        host_registry=registry,
    )
    original_agent_complete = agent_operations.complete

    def ordered_complete(principal_value, receipt_value):  # type: ignore[no-untyped-def]
        ordered_states.append(operations.get(planned.id).state)
        return original_agent_complete(principal_value, receipt_value)

    monkeypatch.setattr(agent_operations, "complete", ordered_complete)
    completed = owner.complete(principal, receipt)

    expected_admin_state = "succeeded" if receipt_state == "succeeded" else "failed"
    assert completed.state == receipt_state
    assert operations.get(planned.id).state == expected_admin_state
    assert agent_operations.get(lease.operation_id).state == receipt_state
    assert ordered_states
    assert set(ordered_states) <= {"succeeded", "failed"}
    assert registry.get("worker-one").generation == (
        5 if receipt_state == "succeeded" else 4
    )


@pytest.mark.parametrize("receipt_state", ("succeeded", "failed", "unknown"))
def test_legacy_terminal_pair_migrates_to_acknowledged_replay_tombstone(
    tmp_path: Path,
    receipt_state: str,
) -> None:
    now = [NOW]

    def clock() -> datetime:
        return now[0]

    owner, operations, agent_operations, _registry, principal, lease, operation_id = (
        _remote_scenario(tmp_path, clock=clock)
    )
    receipt = _receipt(lease, state=receipt_state)
    terminal_agent = owner.complete(principal, receipt)
    terminal_admin = operations.get(operation_id)
    registry_path = _registry_document(tmp_path)
    registry_after_completion = registry_path.read_bytes()
    lifecycle_path = (
        tmp_path / "admin-operations" / "host-probe-lifecycle.json"
    )
    lifecycle_path.unlink()
    now[0] += timedelta(minutes=16)

    operations.plan(
        kind="google.provision",
        generation=4,
        key=f"ordinary-prune-terminal-{receipt_state}",
        steps=("one",),
    )

    with pytest.raises(AdminOperationError, match="control.operation_not_found"):
        operations.get(operation_id)
    lifecycle = json.loads(lifecycle_path.read_text(encoding="utf-8"))
    assert lifecycle["schema_version"] == 1
    assert lifecycle["owners"] == [
        {
            "acknowledged": True,
            "agent_operation_id": lease.operation_id,
            "expected_generation": terminal_admin.expected_generation,
            "operation_id": operation_id,
            "plan_digest": lease.plan_digest,
            "target_host_ref": "worker-one",
        }
    ]

    operations = AdminOperationStore.for_test(tmp_path, clock=clock)
    agent_operations = AgentOperationStore.for_test(tmp_path, clock=clock)
    replayed = RemoteHostProbeCompletionOwner(
        operation_store=operations,
        agent_operations=agent_operations,
        host_registry=HostRegistry.for_test(tmp_path),
    ).complete(principal, receipt)

    assert replayed == terminal_agent
    assert registry_path.read_bytes() == registry_after_completion


def test_legacy_terminal_admin_with_leased_agent_is_protected_then_converges(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = [NOW]

    def clock() -> datetime:
        return now[0]

    owner, operations, agent_operations, _registry, principal, lease, operation_id = (
        _remote_scenario(tmp_path, clock=clock)
    )
    receipt = _receipt(lease)
    original_complete = agent_operations.complete
    attempts = 0

    def fail_agent_write_once(*args: object, **kwargs: object) -> object:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise AgentOperationError("host.operation_store_unavailable")
        return original_complete(*args, **kwargs)

    monkeypatch.setattr(agent_operations, "complete", fail_agent_write_once)
    with pytest.raises(AgentOperationError, match="host.operation_store_unavailable"):
        owner.complete(principal, receipt)
    assert operations.get(operation_id).state == "succeeded"
    assert agent_operations.get(lease.operation_id).state == "leased"
    registry_path = _registry_document(tmp_path)
    registry_after_admin = registry_path.read_bytes()
    lifecycle_path = (
        tmp_path / "admin-operations" / "host-probe-lifecycle.json"
    )
    lifecycle_path.unlink()
    now[0] += timedelta(minutes=16)

    operations.plan(
        kind="google.provision",
        generation=4,
        key="ordinary-prune-terminal-admin-crash-window",
        steps=("one",),
    )

    assert operations.get(operation_id).state == "succeeded"
    lifecycle = json.loads(lifecycle_path.read_text(encoding="utf-8"))
    assert lifecycle["owners"][0]["acknowledged"] is False
    lifecycle_owner = RemoteHostProbeCompletionOwner(
        operation_store=operations,
        agent_operations=agent_operations,
        host_registry=HostRegistry.for_test(tmp_path),
    )
    agent_operations.expire_leases(
        operation_deadline_owner=lifecycle_owner.reconcile_operation_deadline,
        lifecycle_ack_owner=lifecycle_owner.acknowledge_agent_lifecycle,
        owner_host_ref="worker-one",
    )
    terminal_agent = agent_operations.get(lease.operation_id)
    assert terminal_agent.state == "unknown"
    assert terminal_agent.reason_codes == ("host.lease_expired",)
    assert registry_path.read_bytes() == registry_after_admin

    operations.plan(
        kind="google.provision",
        generation=4,
        key="ordinary-prune-after-terminal-crash-ack",
        steps=("one",),
    )
    with pytest.raises(AdminOperationError, match="control.operation_not_found"):
        operations.get(operation_id)
    assert AgentOperationStore.for_test(
        tmp_path,
        clock=clock,
    ).get(lease.operation_id) == terminal_agent


def test_legacy_bool_schema_migration_fails_before_any_durable_mutation(
    tmp_path: Path,
) -> None:
    now = [NOW]

    def clock() -> datetime:
        return now[0]

    _owner, operations, _agent_operations, _registry, _principal, _lease, _operation_id = (
        _remote_scenario(tmp_path, clock=clock)
    )
    lifecycle_path = (
        tmp_path / "admin-operations" / "host-probe-lifecycle.json"
    )
    lifecycle_path.unlink()
    agent_path = tmp_path / "agent-operations" / "operations.json"
    agent_document = json.loads(agent_path.read_text(encoding="utf-8"))
    arguments = agent_document["operations"][0]["arguments"]
    arguments["probe_schema"] = True
    agent_document["operations"][0]["arguments_digest"] = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(
                arguments,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
    )
    agent_path.write_text(
        json.dumps(agent_document, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    agent_path.chmod(0o600)
    now[0] += timedelta(minutes=16)
    admin_path = tmp_path / "admin-operations" / "operations.json"
    before_admin = admin_path.read_bytes()
    before_agent = agent_path.read_bytes()

    with pytest.raises(AdminOperationError, match="control.operation_store_unavailable"):
        operations.plan(
            kind="google.provision",
            generation=4,
            key="invalid-bool-migration",
            steps=("one",),
        )

    assert admin_path.read_bytes() == before_admin
    assert agent_path.read_bytes() == before_agent
    assert not lifecycle_path.exists()


@pytest.mark.parametrize("boundary", ("attempt_exhaustion", "operation_deadline"))
def test_lifecycle_boundaries_reject_bool_schema_before_mutation(
    tmp_path: Path,
    boundary: str,
) -> None:
    owner, _operations, agent_operations, _registry, _principal, lease, _operation_id = (
        _remote_scenario(tmp_path)
    )
    invalid_arguments = {
        "admin_operation_id": lease.arguments["admin_operation_id"],
        "probe_schema": True,
    }
    if boundary == "attempt_exhaustion":
        context: AgentAttemptExhaustionV1 | AgentOperationDeadlineExpiryV1 = (
            AgentAttemptExhaustionV1(
                lease.operation_id,
                lease.host_ref,
                lease.host_ref,
                lease.kind,
                lease.action,
                lease.registry_generation,
                lease.attempt,
                lease.plan_digest,
                lease.arguments_digest,
                invalid_arguments,
                lease.lease_id,
                lease.lease_epoch,
                lease.deadline,
            )
        )
        callback = owner.reconcile_attempt_exhaustion
    else:
        context = AgentOperationDeadlineExpiryV1(
            lease.operation_id,
            lease.host_ref,
            lease.host_ref,
            lease.kind,
            lease.action,
            lease.registry_generation,
            lease.attempt,
            lease.plan_digest,
            lease.arguments_digest,
            invalid_arguments,
            agent_operations.get(lease.operation_id).deadline,
            lease.lease_id,
            lease.registry_generation,
            lease.lease_epoch,
            lease.deadline,
        )
        callback = owner.reconcile_operation_deadline
    paths = (
        tmp_path / "admin-operations" / "operations.json",
        tmp_path / "agent-operations" / "operations.json",
        tmp_path / "admin-hosts" / "hosts.json",
        tmp_path / "admin-operations" / "host-probe-lifecycle.json",
    )
    before = tuple(path.read_bytes() for path in paths)

    with pytest.raises(HostProbeError):
        callback(context)  # type: ignore[arg-type]

    assert tuple(path.read_bytes() for path in paths) == before


def test_lifecycle_ack_rejects_bool_schema_before_sidecar_mutation(
    tmp_path: Path,
) -> None:
    now = [NOW]

    def clock() -> datetime:
        return now[0]

    owner, operations, agent_operations, _registry, _principal, lease, operation_id = (
        _remote_scenario(tmp_path, clock=clock)
    )
    now[0] += timedelta(minutes=16)
    agent_operations.expire_leases()
    operations.expire_host_probe(
        operation_id,
        expected_generation=4,
        plan_digest=lease.plan_digest,
    )
    context = AgentOperationDeadlineExpiryV1(
        lease.operation_id,
        lease.host_ref,
        lease.host_ref,
        lease.kind,
        lease.action,
        lease.registry_generation,
        lease.attempt,
        lease.plan_digest,
        lease.arguments_digest,
        {
            "admin_operation_id": operation_id,
            "probe_schema": True,
        },
        agent_operations.get(lease.operation_id).deadline,
        lease.lease_id,
        lease.registry_generation,
        lease.lease_epoch,
        lease.deadline,
    )
    paths = (
        tmp_path / "admin-operations" / "operations.json",
        tmp_path / "agent-operations" / "operations.json",
        tmp_path / "admin-hosts" / "hosts.json",
        tmp_path / "admin-operations" / "host-probe-lifecycle.json",
    )
    before = tuple(path.read_bytes() for path in paths)

    with pytest.raises(HostProbeError):
        owner.acknowledge_agent_lifecycle(context)

    assert tuple(path.read_bytes() for path in paths) == before


def test_completion_rejects_persisted_bool_schema_before_mutation(
    tmp_path: Path,
) -> None:
    owner, _operations, _agent_operations, _registry, principal, lease, _operation_id = (
        _remote_scenario(tmp_path)
    )
    invalid_arguments = dict(lease.arguments)
    invalid_arguments["probe_schema"] = True
    invalid_digest = "sha256:" + hashlib.sha256(
        json.dumps(
            invalid_arguments,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    agent_path = tmp_path / "agent-operations" / "operations.json"
    document = json.loads(agent_path.read_text(encoding="utf-8"))
    document["operations"][0]["arguments"] = invalid_arguments
    document["operations"][0]["arguments_digest"] = invalid_digest
    agent_path.write_text(
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    agent_path.chmod(0o600)
    invalid_lease = replace(
        lease,
        arguments=invalid_arguments,
        arguments_digest=invalid_digest,
    )
    paths = (
        tmp_path / "admin-operations" / "operations.json",
        agent_path,
        tmp_path / "admin-hosts" / "hosts.json",
        tmp_path / "admin-operations" / "host-probe-lifecycle.json",
    )
    before = tuple(path.read_bytes() for path in paths)

    with pytest.raises(HostProbeError):
        owner.complete(principal, _receipt(invalid_lease))

    assert tuple(path.read_bytes() for path in paths) == before


def test_migration_rejects_duplicate_sidecar_agent_owner_without_partial_write(
    tmp_path: Path,
) -> None:
    now = [NOW]

    def clock() -> datetime:
        return now[0]

    operations = AdminOperationStore.for_test(tmp_path, clock=clock)
    agent_operations = AgentOperationStore.for_test(tmp_path, clock=clock)
    first = operations.plan(
        kind="hosts.probe",
        generation=4,
        key="existing-sidecar-owner",
        steps=("host.probe.collect",),
    )
    second = operations.plan(
        kind="hosts.probe",
        generation=4,
        key="legacy-migration-candidate",
        steps=("host.probe.collect",),
    )
    agent = agent_operations.enqueue(
        AgentOperationRequestV1(
            key="ambiguous-agent-owner",
            kind="host.probe",
            action="collect",
            registry_generation=1,
            plan_digest=second.plan_digest,
            arguments={
                "admin_operation_id": second.operation_id,
                "probe_schema": 1,
            },
            deadline=NOW + timedelta(minutes=5),
            target_host_ref="worker-one",
        )
    )
    operations.bind_host_probe_agent(
        first.operation_id,
        agent_operation_id=agent.operation_id,
        target_host_ref="worker-one",
        plan_digest=first.plan_digest,
    )
    now[0] += timedelta(minutes=16)
    paths = (
        tmp_path / "admin-operations" / "operations.json",
        tmp_path / "agent-operations" / "operations.json",
        tmp_path / "admin-operations" / "host-probe-lifecycle.json",
    )
    before = tuple(path.read_bytes() for path in paths)

    with pytest.raises(AdminOperationError, match="control.operation_store_unavailable"):
        operations.plan(
            kind="google.provision",
            generation=4,
            key="ambiguous-migration-trigger",
            steps=("one",),
        )

    assert tuple(path.read_bytes() for path in paths) == before


@pytest.mark.parametrize(
    "mutation",
    ("incompatible_state", "wrong_host", "wrong_plan"),
)
def test_legacy_terminal_migration_rejects_inexact_pair_without_mutation(
    tmp_path: Path,
    mutation: str,
) -> None:
    now = [NOW]

    def clock() -> datetime:
        return now[0]

    owner, operations, _agent_operations, _registry, principal, lease, _operation_id = (
        _remote_scenario(tmp_path, clock=clock)
    )
    owner.complete(principal, _receipt(lease))
    lifecycle_path = (
        tmp_path / "admin-operations" / "host-probe-lifecycle.json"
    )
    lifecycle_path.unlink()
    agent_path = tmp_path / "agent-operations" / "operations.json"
    document = json.loads(agent_path.read_text(encoding="utf-8"))
    record = document["operations"][0]
    if mutation == "incompatible_state":
        record["state"] = "failed"
        record["completion"]["reason_codes"] = ["host.probe_unknown"]
    elif mutation == "wrong_host":
        record["lease"]["host_ref"] = "worker-two"
    else:
        record["plan_digest"] = "sha256:" + "0" * 64
    agent_path.write_text(
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    agent_path.chmod(0o600)
    now[0] += timedelta(minutes=16)
    admin_path = tmp_path / "admin-operations" / "operations.json"
    before_admin = admin_path.read_bytes()
    before_agent = agent_path.read_bytes()

    with pytest.raises(AdminOperationError, match="control.operation_store_unavailable"):
        operations.plan(
            kind="google.provision",
            generation=4,
            key=f"reject-inexact-terminal-{mutation}",
            steps=("one",),
        )

    assert admin_path.read_bytes() == before_admin
    assert agent_path.read_bytes() == before_agent
    assert not lifecycle_path.exists()


def test_legacy_receipt_terminal_cannot_authorize_nonterminal_admin_pair(
    tmp_path: Path,
) -> None:
    now = [NOW]

    def clock() -> datetime:
        return now[0]

    _owner, operations, agent_operations, _registry, principal, lease, _operation_id = (
        _remote_scenario(tmp_path, clock=clock)
    )
    lifecycle_path = (
        tmp_path / "admin-operations" / "host-probe-lifecycle.json"
    )
    lifecycle_path.unlink()
    agent_operations.complete(
        OperationPrincipalV1(principal.host_ref, principal.registry_generation),
        _receipt(lease),
    )
    now[0] += timedelta(minutes=16)
    admin_path = tmp_path / "admin-operations" / "operations.json"
    agent_path = tmp_path / "agent-operations" / "operations.json"
    before = (admin_path.read_bytes(), agent_path.read_bytes())

    with pytest.raises(AdminOperationError, match="control.operation_store_unavailable"):
        operations.plan(
            kind="google.provision",
            generation=4,
            key="reject-terminal-agent-planned-admin",
            steps=("one",),
        )

    assert (admin_path.read_bytes(), agent_path.read_bytes()) == before
    assert not lifecycle_path.exists()


class _DeadOwner:
    def current(self) -> tuple[str, int, int]:
        return ("11111111-1111-1111-1111-111111111111", 1234, 99)

    def is_alive(self, _owner: tuple[str, int, int]) -> bool:
        return False


def test_conflicting_success_receipt_preserves_restart_failure_without_registry_write(
    tmp_path: Path,
) -> None:
    owner, operations, agent_operations, registry, principal, lease, operation_id = (
        _remote_scenario(tmp_path)
    )
    operations.begin(operation_id, current_generation=4)
    operations.record_step(
        operation_id,
        "host.probe.collect",
        succeeded=False,
        reason_code="host.probe_failed",
    )
    operations = AdminOperationStore.for_test(
        tmp_path,
        clock=lambda: NOW,
        owner_probe=_DeadOwner(),
    )
    assert operations.get(operation_id).state == "partial"
    registry_path = _registry_document(tmp_path)
    registry_before = registry_path.read_bytes()
    owner = RemoteHostProbeCompletionOwner(
        operation_store=operations,
        agent_operations=agent_operations,
        host_registry=registry,
    )
    receipt = _receipt(lease)

    completed = owner.complete(principal, receipt)

    assert completed.state == "succeeded"
    terminal_admin = operations.get(operation_id)
    assert terminal_admin.state == "failed"
    assert terminal_admin.reason_codes == ("host.probe_failed",)
    assert agent_operations.get(lease.operation_id).state == "succeeded"
    assert registry_path.read_bytes() == registry_before

    operations = AdminOperationStore.for_test(
        tmp_path,
        clock=lambda: NOW,
        owner_probe=_DeadOwner(),
    )
    replayed = RemoteHostProbeCompletionOwner(
        operation_store=operations,
        agent_operations=AgentOperationStore.for_test(
            tmp_path,
            clock=lambda: NOW,
        ),
        host_registry=HostRegistry.for_test(tmp_path),
    ).complete(principal, receipt)
    assert replayed == completed
    assert operations.get(operation_id) == terminal_admin
    assert registry_path.read_bytes() == registry_before
