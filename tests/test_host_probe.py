from __future__ import annotations

import json
import hashlib
from datetime import UTC, datetime
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
    AgentOperationError,
    AgentOperationStore,
    AgentPrincipalV1 as OperationPrincipalV1,
)
from codex_master.host_probe import (
    HostProbeError,
    HostProbeEvidenceV1,
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
) -> tuple[
    RemoteHostProbeCompletionOwner,
    AdminOperationStore,
    AgentOperationStore,
    HostRegistry,
    RegistryPrincipalV1,
    AgentLeaseV1,
    str,
]:
    registry = HostRegistry.for_test(tmp_path)
    registry.record_probe("worker-one", generation=4, evidence=_registry_evidence())
    operations = AdminOperationStore.for_test(tmp_path, clock=lambda: NOW)
    agent_operations = AgentOperationStore.for_test(tmp_path, clock=lambda: NOW)
    adapter = RemoteHostProbeAdapter(
        operation_store=operations,
        agent_operations=agent_operations,
        clock=lambda: NOW,
    )
    planned = adapter.probe(
        "worker-one", expected_generation=4, idempotency_key="probe-one"
    )
    operation_principal = OperationPrincipalV1("worker-one", 4)
    lease = agent_operations.poll(
        operation_principal,
        AgentPollV1(4, 1, CAPABILITIES_DIGEST, 0),
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
        RegistryPrincipalV1("worker-one", 4, 1),
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
    operations = AdminOperationStore.for_test(tmp_path, clock=lambda: NOW)
    agent_operations = AgentOperationStore.for_test(tmp_path, clock=lambda: NOW)
    adapter = RemoteHostProbeAdapter(
        operation_store=operations,
        agent_operations=agent_operations,
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
