from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
from typing import cast

import pytest

from codex_master.admin_hosts import AgentBindingV1, HostRegistry
from codex_master.admin_operations import AdminOperationStore
from codex_master.agent_contracts import AgentReceiptV1, parse_agent_receipt
from codex_master.agent_http import AgentHttpApplication
from codex_master.agent_operations import AgentOperationError, AgentOperationStore
from codex_master.host_agent import (
    HostAgent,
    HostAgentClient,
    HostAgentError,
    HostAgentExecutor,
    HostProbeExecutor,
)
from codex_master.host_agent_state import HostAgentState
from codex_master.host_probe import (
    HostProbeEvidenceV1,
    LocalHostProbeCollector,
    RemoteHostProbeAdapter,
    RemoteHostProbeCompletionOwner,
)


CAPABILITIES_DIGEST = "sha256:" + "c" * 64
SPKI_ONE = "sha256:" + "1" * 64
SPKI_TWO = "sha256:" + "2" * 64
OBSERVED_AT = datetime(2026, 8, 31, 8, 0, tzinfo=UTC)


class DeterministicKernel:
    cpu_count = 8
    memory_bytes = 16 * 1024**3

    def uname(self) -> tuple[str, str]:
        return "Linux", "x86_64"

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


class InProcessAgentClient(HostAgentClient):
    """Replace only TLS/socket transport while retaining the real client protocol."""

    def __init__(
        self,
        application: AgentHttpApplication,
        registry: HostRegistry,
        *,
        client_spki_sha256: str,
    ) -> None:
        self.application = application
        self.registry = registry
        self.client_spki_sha256 = client_spki_sha256
        self.receipts: list[AgentReceiptV1] = []
        self.before_application: Callable[[str], None] | None = None

    def _request(self, target: str, value: object) -> dict[str, object]:
        body = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        principal = self.registry.resolve_agent_spki(self.client_spki_sha256)
        if "/receipts" in target:
            self.receipts.append(parse_agent_receipt(cast(dict[str, object], value)))
        if self.before_application is not None:
            self.before_application(target)
        response = self.application.handle(principal, "POST", target, body)
        if response.status != 200:
            raise HostAgentError("resource.host_response_invalid")
        result = json.loads(response.body)
        return cast(dict[str, object], result)


def _registration(ref: str, label: str) -> dict[str, object]:
    return {
        "ref": ref,
        "label": label,
        "role": "execution",
        "capabilities": ["resource.probe", "codex.execute"],
    }


def _bindings_document(state_root: Path) -> dict[str, object]:
    document = json.loads(
        (state_root / "admin-hosts" / "hosts.json").read_text(encoding="utf-8")
    )
    return cast(dict[str, object], document["bindings"])


class MutableClock:
    def __init__(self) -> None:
        self.now = datetime.now(UTC).replace(microsecond=0)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, *, seconds: int) -> None:
        self.now += timedelta(seconds=seconds)


def test_real_production_graph_closes_remote_probe_and_repolls_after_generation_change(
    tmp_path: Path,
) -> None:
    registry = HostRegistry(tmp_path)
    target = registry.provision_agent_binding(
        _registration("worker-one", "Worker One"),
        AgentBindingV1("worker-one", SPKI_ONE, 1, True),
        expected_generation=0,
    )
    registry.provision_agent_binding(
        _registration("worker-two", "Worker Two"),
        AgentBindingV1("worker-two", SPKI_TWO, 1, True),
        expected_generation=1,
    )
    principal = registry.resolve_agent_spki(SPKI_ONE)
    assert target.generation == 1
    assert principal.registry_generation == 2
    bindings_before = _bindings_document(tmp_path)

    admin_operations = AdminOperationStore(tmp_path)
    agent_operations = AgentOperationStore(tmp_path)
    planned = RemoteHostProbeAdapter(
        operation_store=admin_operations,
        agent_operations=agent_operations,
        host_registry=registry,
    ).probe(
        "worker-one",
        expected_generation=target.generation,
        idempotency_key="production-graph-probe",
    )
    terminal_order: list[str] = []
    original_agent_complete = agent_operations.complete

    def ordered_agent_complete(principal_value, receipt_value):  # type: ignore[no-untyped-def]
        terminal_order.append(admin_operations.get(planned.id).state)
        return original_agent_complete(principal_value, receipt_value)

    agent_operations.complete = ordered_agent_complete  # type: ignore[method-assign]
    completion_owner = RemoteHostProbeCompletionOwner(
        operation_store=admin_operations,
        agent_operations=agent_operations,
        host_registry=registry,
    )
    application = AgentHttpApplication(agent_operations, completion_owner)
    client = InProcessAgentClient(
        application,
        registry,
        client_spki_sha256=SPKI_ONE,
    )
    evidence = LocalHostProbeCollector(lambda: OBSERVED_AT).collect(
        DeterministicKernel()
    )
    executor = HostAgentExecutor(
        state=HostAgentState(tmp_path / "worker-one-state", host_ref="worker-one"),
        ollama=object(),
        host_probe=HostProbeExecutor(
            collector=LocalHostProbeCollector(lambda: OBSERVED_AT),
            kernel=DeterministicKernel(),
        ),
    )
    agent = HostAgent(
        client=client,
        executor=executor,
        registry_generation=principal.registry_generation,
        lease_epoch=principal.lease_epoch,
        capabilities_digest=CAPABILITIES_DIGEST,
    )

    assert agent.run_once(max_wait_seconds=0) == 0

    assert len(client.receipts) == 1
    receipt = client.receipts[0]
    assert receipt.result.payload == evidence.public()
    assert HostProbeEvidenceV1.from_public(dict(receipt.result.payload)) == evidence
    assert admin_operations.get(planned.id).state == "succeeded"
    assert agent_operations.get(receipt.operation_id).state == "succeeded"
    refreshed = registry.get("worker-one")
    assert refreshed.generation == 2
    assert registry.document_generation() == 3
    assert _bindings_document(tmp_path) == bindings_before
    assert terminal_order == ["succeeded"]

    assert agent.run_once(max_wait_seconds=0) == 0
    assert len(client.receipts) == 1


def test_real_production_loop_recovers_rejected_receipt_after_master_reconstruction(
    tmp_path: Path,
) -> None:
    class CountingKernel(DeterministicKernel):
        collections = 0

        def uname(self) -> tuple[str, str]:
            self.collections += 1
            return super().uname()

    clock = MutableClock()
    registry = HostRegistry(tmp_path)
    target = registry.provision_agent_binding(
        _registration("worker-one", "Worker One"),
        AgentBindingV1("worker-one", SPKI_ONE, 1, True),
        expected_generation=0,
    )
    registry.provision_agent_binding(
        _registration("worker-two", "Worker Two"),
        AgentBindingV1("worker-two", SPKI_TWO, 1, True),
        expected_generation=1,
    )
    principal = registry.resolve_agent_spki(SPKI_ONE)
    admin_operations = AdminOperationStore(tmp_path, clock=clock)
    agent_operations = AgentOperationStore(tmp_path, clock=clock)
    planned = RemoteHostProbeAdapter(
        operation_store=admin_operations,
        agent_operations=agent_operations,
        host_registry=registry,
        clock=clock,
    ).probe(
        "worker-one",
        expected_generation=target.generation,
        idempotency_key="rejected-receipt-recovery",
    )
    application = AgentHttpApplication(
        agent_operations,
        RemoteHostProbeCompletionOwner(
            operation_store=admin_operations,
            agent_operations=agent_operations,
            host_registry=registry,
        ),
    )
    client = InProcessAgentClient(
        application,
        registry,
        client_spki_sha256=SPKI_ONE,
    )
    kernel = CountingKernel()
    agent_state_root = tmp_path / "worker-one-state"
    agent = HostAgent(
        client=client,
        executor=HostAgentExecutor(
            state=HostAgentState(agent_state_root, host_ref="worker-one"),
            ollama=object(),
            host_probe=HostProbeExecutor(
                collector=LocalHostProbeCollector(lambda: OBSERVED_AT),
                kernel=kernel,
            ),
        ),
        registry_generation=principal.registry_generation,
        lease_epoch=principal.lease_epoch,
        capabilities_digest=CAPABILITIES_DIGEST,
    )
    registry_document = tmp_path / "admin-hosts" / "hosts.json"
    healthy_registry = registry_document.read_bytes()

    def corrupt_during_receipt(target_path: str) -> None:
        if "/receipts" not in target_path:
            return
        client.before_application = None
        registry_document.write_bytes(b"{corrupt")
        registry_document.chmod(0o600)

    client.before_application = corrupt_during_receipt
    with pytest.raises(HostAgentError, match="resource.host_response_invalid"):
        agent.run_once(max_wait_seconds=0)

    assert kernel.collections == 1
    assert admin_operations.get(planned.id).state == "planned"
    assert len(client.receipts) == 1
    queued_id = client.receipts[0].operation_id
    assert agent_operations.get(queued_id).state == "leased"

    registry_document.write_bytes(healthy_registry)
    registry_document.chmod(0o600)
    clock.advance(seconds=31)

    admin_operations = AdminOperationStore(tmp_path, clock=clock)
    agent_operations = AgentOperationStore(tmp_path, clock=clock)
    registry = HostRegistry(tmp_path)
    registry_writes = 0
    original_registry_write = registry._write_locked

    def counted_registry_write(*arguments: object, **keywords: object) -> object:
        nonlocal registry_writes
        registry_writes += 1
        return original_registry_write(*arguments, **keywords)

    registry._write_locked = counted_registry_write  # type: ignore[method-assign]
    agent_terminal_order: list[str] = []
    original_agent_complete = agent_operations.complete

    def ordered_agent_complete(principal_value, receipt_value):  # type: ignore[no-untyped-def]
        agent_terminal_order.append(admin_operations.get(planned.id).state)
        return original_agent_complete(principal_value, receipt_value)

    agent_operations.complete = ordered_agent_complete  # type: ignore[method-assign]
    application = AgentHttpApplication(
        agent_operations,
        RemoteHostProbeCompletionOwner(
            operation_store=admin_operations,
            agent_operations=agent_operations,
            host_registry=registry,
        ),
    )
    client = InProcessAgentClient(
        application,
        registry,
        client_spki_sha256=SPKI_ONE,
    )
    recovered_agent = HostAgent(
        client=client,
        executor=HostAgentExecutor(
            state=HostAgentState(agent_state_root, host_ref="worker-one"),
            ollama=object(),
            host_probe=HostProbeExecutor(
                collector=LocalHostProbeCollector(lambda: OBSERVED_AT),
                kernel=kernel,
            ),
        ),
        registry_generation=principal.registry_generation,
        lease_epoch=principal.lease_epoch,
        capabilities_digest=CAPABILITIES_DIGEST,
    )

    assert recovered_agent.run_once(max_wait_seconds=0) == 0

    assert kernel.collections == 1
    assert len(client.receipts) == 1
    assert client.receipts[0].attempt == 2
    assert admin_operations.get(planned.id).state == "succeeded"
    assert agent_operations.get(queued_id).state == "succeeded"
    assert registry.get("worker-one").generation == 2
    assert registry.document_generation() == 3
    assert registry_writes == 1
    assert agent_terminal_order == ["succeeded"]

    assert recovered_agent.run_once(max_wait_seconds=0) == 0
    assert kernel.collections == 1


def test_real_production_loop_rebinds_after_post_mutation_receipt_rejection(
    tmp_path: Path,
) -> None:
    class CountingKernel(DeterministicKernel):
        collections = 0

        def uname(self) -> tuple[str, str]:
            self.collections += 1
            return super().uname()

    clock = MutableClock()
    registry = HostRegistry(tmp_path)
    target = registry.provision_agent_binding(
        _registration("worker-one", "Worker One"),
        AgentBindingV1("worker-one", SPKI_ONE, 1, True),
        expected_generation=0,
    )
    registry.provision_agent_binding(
        _registration("worker-two", "Worker Two"),
        AgentBindingV1("worker-two", SPKI_TWO, 1, True),
        expected_generation=1,
    )
    principal = registry.resolve_agent_spki(SPKI_ONE)
    admin_operations = AdminOperationStore(tmp_path, clock=clock)
    agent_operations = AgentOperationStore(tmp_path, clock=clock)
    planned = RemoteHostProbeAdapter(
        operation_store=admin_operations,
        agent_operations=agent_operations,
        host_registry=registry,
        clock=clock,
    ).probe(
        "worker-one",
        expected_generation=target.generation,
        idempotency_key="post-mutation-rejection",
    )
    original_complete = agent_operations.complete
    rejected = False

    def reject_agent_terminal_once(*arguments: object, **keywords: object) -> object:
        nonlocal rejected
        if not rejected:
            rejected = True
            raise AgentOperationError("host.operation_store_unavailable")
        return original_complete(*arguments, **keywords)

    agent_operations.complete = reject_agent_terminal_once  # type: ignore[method-assign]
    application = AgentHttpApplication(
        agent_operations,
        RemoteHostProbeCompletionOwner(
            operation_store=admin_operations,
            agent_operations=agent_operations,
            host_registry=registry,
        ),
    )
    client = InProcessAgentClient(
        application,
        registry,
        client_spki_sha256=SPKI_ONE,
    )
    kernel = CountingKernel()
    agent_state_root = tmp_path / "worker-one-state"
    agent = HostAgent(
        client=client,
        executor=HostAgentExecutor(
            state=HostAgentState(agent_state_root, host_ref="worker-one"),
            ollama=object(),
            host_probe=HostProbeExecutor(
                collector=LocalHostProbeCollector(lambda: OBSERVED_AT),
                kernel=kernel,
            ),
        ),
        registry_generation=principal.registry_generation,
        lease_epoch=principal.lease_epoch,
        capabilities_digest=CAPABILITIES_DIGEST,
    )

    with pytest.raises(HostAgentError, match="resource.host_response_invalid"):
        agent.run_once(max_wait_seconds=0)

    queued_id = client.receipts[0].operation_id
    assert kernel.collections == 1
    assert admin_operations.get(planned.id).state == "succeeded"
    assert agent_operations.get(queued_id).state == "leased"
    assert registry.get("worker-one").generation == 2
    assert registry.document_generation() == 3
    clock.advance(seconds=31)

    admin_operations = AdminOperationStore(tmp_path, clock=clock)
    agent_operations = AgentOperationStore(tmp_path, clock=clock)
    registry = HostRegistry(tmp_path)
    recovery_registry_writes = 0
    original_registry_write = registry._write_locked

    def counted_registry_write(*arguments: object, **keywords: object) -> object:
        nonlocal recovery_registry_writes
        recovery_registry_writes += 1
        return original_registry_write(*arguments, **keywords)

    registry._write_locked = counted_registry_write  # type: ignore[method-assign]
    application = AgentHttpApplication(
        agent_operations,
        RemoteHostProbeCompletionOwner(
            operation_store=admin_operations,
            agent_operations=agent_operations,
            host_registry=registry,
        ),
    )
    client = InProcessAgentClient(
        application,
        registry,
        client_spki_sha256=SPKI_ONE,
    )
    recovered = HostAgent(
        client=client,
        executor=HostAgentExecutor(
            state=HostAgentState(agent_state_root, host_ref="worker-one"),
            ollama=object(),
            host_probe=HostProbeExecutor(
                collector=LocalHostProbeCollector(lambda: OBSERVED_AT),
                kernel=kernel,
            ),
        ),
        registry_generation=principal.registry_generation,
        lease_epoch=principal.lease_epoch,
        capabilities_digest=CAPABILITIES_DIGEST,
    )

    assert recovered.run_once(max_wait_seconds=0) == 0

    assert client.receipts[0].attempt == 2
    assert recovered._registry_generation == 3  # type: ignore[attr-defined]
    assert kernel.collections == 1
    assert admin_operations.get(planned.id).state == "succeeded"
    assert agent_operations.get(queued_id).state == "succeeded"
    assert registry.document_generation() == 3
    assert recovery_registry_writes == 0
