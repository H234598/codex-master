from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
import hashlib
import json
from pathlib import Path
from typing import cast

import pytest

from codex_master.admin_hosts import AgentBindingV1, HostRegistry
from codex_master.admin_operations import AdminOperationError, AdminOperationStore
from codex_master.agent_contracts import (
    AgentLeaseV1,
    AgentNoWorkV1,
    AgentPollV1,
    AgentReceiptV1,
    AgentResultV1,
    parse_agent_receipt,
    serialize_agent_result,
)
from codex_master.agent_http import AgentHttpApplication
from codex_master.agent_operations import (
    AgentOperationError,
    AgentOperationRequestV1,
    AgentOperationStore,
)
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


class DeadOwnerProbe:
    def current(self) -> tuple[str, int, int]:
        return ("11111111-1111-1111-1111-111111111111", 1234, 99)

    def is_alive(self, _owner: tuple[str, int, int]) -> bool:
        return False


def _lease_probe_through_attempt_limit(
    client: InProcessAgentClient,
    principal_generation: int,
    lease_epoch: int,
    clock: MutableClock,
) -> str:
    operation_id = ""
    poll = AgentPollV1(
        principal_generation,
        lease_epoch,
        CAPABILITIES_DIGEST,
        0,
    )
    for attempt in range(1, 9):
        lease = client.poll(poll)
        assert isinstance(lease, AgentLeaseV1)
        assert lease.attempt == attempt
        operation_id = lease.operation_id
        clock.advance(seconds=31)
    return operation_id


def _successful_probe_receipt(lease: AgentLeaseV1) -> AgentReceiptV1:
    evidence = LocalHostProbeCollector(lambda: OBSERVED_AT).collect(
        DeterministicKernel()
    )
    result = AgentResultV1("host.probe", "collect", evidence.public())
    result_digest = "sha256:" + hashlib.sha256(
        json.dumps(
            serialize_agent_result(result),
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return AgentReceiptV1(
        lease.operation_id,
        lease.lease_id,
        lease.lease_epoch,
        lease.attempt,
        lease.plan_digest,
        lease.arguments_digest,
        "succeeded",
        ("resource_ready",),
        result_digest,
        result,
    )


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


def test_attempt_exhaustion_reconciles_paired_admin_after_master_restart(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    registry = HostRegistry(tmp_path)
    target = registry.provision_agent_binding(
        _registration("worker-one", "Worker One"),
        AgentBindingV1("worker-one", SPKI_ONE, 1, True),
        expected_generation=0,
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
        idempotency_key="attempt-exhaustion-restart",
    )
    client = InProcessAgentClient(
        AgentHttpApplication(
            agent_operations,
            RemoteHostProbeCompletionOwner(
                operation_store=admin_operations,
                agent_operations=agent_operations,
                host_registry=registry,
            ),
        ),
        registry,
        client_spki_sha256=SPKI_ONE,
    )
    agent_operation_id = _lease_probe_through_attempt_limit(
        client,
        principal.registry_generation,
        principal.lease_epoch,
        clock,
    )
    registry_document = tmp_path / "admin-hosts" / "hosts.json"
    registry_before = registry_document.read_bytes()

    admin_operations = AdminOperationStore(tmp_path, clock=clock)
    agent_operations = AgentOperationStore(tmp_path, clock=clock)
    registry = HostRegistry(tmp_path)
    client = InProcessAgentClient(
        AgentHttpApplication(
            agent_operations,
            RemoteHostProbeCompletionOwner(
                operation_store=admin_operations,
                agent_operations=agent_operations,
                host_registry=registry,
            ),
        ),
        registry,
        client_spki_sha256=SPKI_ONE,
    )

    idle = client.poll(
        AgentPollV1(
            principal.registry_generation,
            principal.lease_epoch,
            CAPABILITIES_DIGEST,
            0,
        )
    )

    assert isinstance(idle, AgentNoWorkV1)
    admin_terminal = admin_operations.get(planned.id)
    agent_terminal = agent_operations.get(agent_operation_id)
    assert admin_terminal.state == "failed"
    assert admin_terminal.reason_codes == ("host.probe_unknown",)
    assert agent_terminal.state == "unknown"
    assert agent_terminal.reason_codes == ("host.attempts_exhausted",)
    assert registry_document.read_bytes() == registry_before


@pytest.mark.parametrize("failure_boundary", ("admin", "agent"))
def test_attempt_exhaustion_retries_one_shot_reconciliation_failure_on_poll(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_boundary: str,
) -> None:
    clock = MutableClock()
    registry = HostRegistry(tmp_path)
    target = registry.provision_agent_binding(
        _registration("worker-one", "Worker One"),
        AgentBindingV1("worker-one", SPKI_ONE, 1, True),
        expected_generation=0,
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
        idempotency_key=f"attempt-exhaustion-{failure_boundary}",
    )
    client = InProcessAgentClient(
        AgentHttpApplication(
            agent_operations,
            RemoteHostProbeCompletionOwner(
                operation_store=admin_operations,
                agent_operations=agent_operations,
                host_registry=registry,
            ),
        ),
        registry,
        client_spki_sha256=SPKI_ONE,
    )
    agent_operation_id = _lease_probe_through_attempt_limit(
        client,
        principal.registry_generation,
        principal.lease_epoch,
        clock,
    )
    registry_document = tmp_path / "admin-hosts" / "hosts.json"
    registry_before = registry_document.read_bytes()
    failures = 0

    if failure_boundary == "admin":
        original_finish = admin_operations.finish

        def fail_once(*args: object, **kwargs: object) -> object:
            nonlocal failures
            failures += 1
            if failures == 1:
                raise AdminOperationError("control.operation_store_unavailable")
            return original_finish(*args, **kwargs)

        monkeypatch.setattr(admin_operations, "finish", fail_once)
    else:
        original_write = agent_operations._write_locked

        def fail_final_agent_write_once(document: object) -> None:
            nonlocal failures
            if isinstance(document, dict) and any(
                record.get("state") == "unknown"
                and record.get("completion")
                == {
                    "reason_codes": ["host.attempts_exhausted"],
                    "result_digest": None,
                }
                for record in document.get("operations", ())
                if isinstance(record, dict)
            ):
                failures += 1
                if failures == 1:
                    raise AgentOperationError("host.operation_store_unavailable")
            original_write(cast(dict[str, object], document))

        monkeypatch.setattr(
            agent_operations,
            "_write_locked",
            fail_final_agent_write_once,
        )

    poll = AgentPollV1(
        principal.registry_generation,
        principal.lease_epoch,
        CAPABILITIES_DIGEST,
        0,
    )
    with pytest.raises(HostAgentError, match="resource.host_response_invalid"):
        client.poll(poll)

    assert agent_operations.get(agent_operation_id).state == "leased"
    if failure_boundary == "agent":
        assert admin_operations.get(planned.id).state == "failed"
    assert registry_document.read_bytes() == registry_before

    idle = client.poll(poll)

    assert isinstance(idle, AgentNoWorkV1)
    assert admin_operations.get(planned.id).state == "failed"
    assert admin_operations.get(planned.id).reason_codes == ("host.probe_unknown",)
    assert agent_operations.get(agent_operation_id).state == "unknown"
    assert agent_operations.get(agent_operation_id).reason_codes == (
        "host.attempts_exhausted",
    )
    assert failures >= 1
    assert registry_document.read_bytes() == registry_before


def test_attempt_exhaustion_reconciliation_is_scoped_to_polling_host(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    registry = HostRegistry(tmp_path)
    first = registry.provision_agent_binding(
        _registration("worker-one", "Worker One"),
        AgentBindingV1("worker-one", SPKI_ONE, 1, True),
        expected_generation=0,
    )
    second = registry.provision_agent_binding(
        _registration("worker-two", "Worker Two"),
        AgentBindingV1("worker-two", SPKI_TWO, 1, True),
        expected_generation=1,
    )
    first_principal = registry.resolve_agent_spki(SPKI_ONE)
    second_principal = registry.resolve_agent_spki(SPKI_TWO)
    admin_operations = AdminOperationStore(tmp_path, clock=clock)
    agent_operations = AgentOperationStore(tmp_path, clock=clock)
    adapter = RemoteHostProbeAdapter(
        operation_store=admin_operations,
        agent_operations=agent_operations,
        host_registry=registry,
        clock=clock,
    )
    first_plan = adapter.probe(
        "worker-one",
        expected_generation=first.generation,
        idempotency_key="attempt-exhaustion-worker-one",
    )
    second_plan = adapter.probe(
        "worker-two",
        expected_generation=second.generation,
        idempotency_key="attempt-exhaustion-worker-two",
    )
    application = AgentHttpApplication(
        agent_operations,
        RemoteHostProbeCompletionOwner(
            operation_store=admin_operations,
            agent_operations=agent_operations,
            host_registry=registry,
        ),
    )
    first_client = InProcessAgentClient(
        application,
        registry,
        client_spki_sha256=SPKI_ONE,
    )
    second_client = InProcessAgentClient(
        application,
        registry,
        client_spki_sha256=SPKI_TWO,
    )
    first_poll = AgentPollV1(
        first_principal.registry_generation,
        first_principal.lease_epoch,
        CAPABILITIES_DIGEST,
        0,
    )
    second_poll = AgentPollV1(
        second_principal.registry_generation,
        second_principal.lease_epoch,
        CAPABILITIES_DIGEST,
        0,
    )
    first_agent_operation = ""
    second_agent_operation = ""
    for attempt in range(1, 9):
        first_lease = first_client.poll(first_poll)
        second_lease = second_client.poll(second_poll)
        assert isinstance(first_lease, AgentLeaseV1)
        assert isinstance(second_lease, AgentLeaseV1)
        assert first_lease.attempt == second_lease.attempt == attempt
        first_agent_operation = first_lease.operation_id
        second_agent_operation = second_lease.operation_id
        clock.advance(seconds=31)
    registry_document = tmp_path / "admin-hosts" / "hosts.json"
    registry_before = registry_document.read_bytes()

    assert isinstance(first_client.poll(first_poll), AgentNoWorkV1)

    assert admin_operations.get(first_plan.id).state == "failed"
    assert agent_operations.get(first_agent_operation).state == "unknown"
    assert admin_operations.get(second_plan.id).state == "planned"
    assert agent_operations.get(second_agent_operation).state == "leased"

    assert isinstance(second_client.poll(second_poll), AgentNoWorkV1)

    assert admin_operations.get(second_plan.id).state == "failed"
    assert agent_operations.get(second_agent_operation).state == "unknown"
    assert registry_document.read_bytes() == registry_before


def test_persisted_attempt_exhaustion_split_reconciles_after_reconstruction(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    registry = HostRegistry(tmp_path)
    target = registry.provision_agent_binding(
        _registration("worker-one", "Worker One"),
        AgentBindingV1("worker-one", SPKI_ONE, 1, True),
        expected_generation=0,
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
        idempotency_key="persisted-attempt-exhaustion-split",
    )
    client = InProcessAgentClient(
        AgentHttpApplication(agent_operations),
        registry,
        client_spki_sha256=SPKI_ONE,
    )
    agent_operation_id = _lease_probe_through_attempt_limit(
        client,
        principal.registry_generation,
        principal.lease_epoch,
        clock,
    )
    agent_operations.expire_leases()
    persisted_agent = agent_operations.get(agent_operation_id)
    assert persisted_agent.state == "unknown"
    assert persisted_agent.reason_codes == ("host.attempts_exhausted",)
    assert admin_operations.get(planned.id).state == "planned"
    (tmp_path / "admin-operations" / "host-probe-lifecycle.json").unlink()
    admin_document_path = tmp_path / "admin-operations" / "operations.json"
    admin_document = json.loads(admin_document_path.read_text(encoding="utf-8"))
    admin_document["schema_version"] = 1
    for record in admin_document["operations"]:
        record.pop("owner")
    admin_document_path.write_text(json.dumps(admin_document), encoding="utf-8")
    admin_document_path.chmod(0o600)
    registry_document = tmp_path / "admin-hosts" / "hosts.json"
    registry_before = registry_document.read_bytes()
    clock.advance(
        seconds=int((planned.expires_at - clock.now).total_seconds()) + 1
    )
    assert clock.now > planned.expires_at

    admin_operations.plan(
        kind="google.provision",
        generation=1,
        key="ordinary-prune-before-split-reconciliation",
        steps=("one",),
    )
    assert admin_operations.get(planned.id).state == "planned"

    admin_operations = AdminOperationStore(tmp_path, clock=clock)
    agent_operations = AgentOperationStore(tmp_path, clock=clock)
    registry = HostRegistry(tmp_path)
    client = InProcessAgentClient(
        AgentHttpApplication(
            agent_operations,
            RemoteHostProbeCompletionOwner(
                operation_store=admin_operations,
                agent_operations=agent_operations,
                host_registry=registry,
            ),
        ),
        registry,
        client_spki_sha256=SPKI_ONE,
    )
    poll = AgentPollV1(
        principal.registry_generation,
        principal.lease_epoch,
        CAPABILITIES_DIGEST,
        0,
    )

    assert isinstance(client.poll(poll), AgentNoWorkV1)
    terminal_admin = admin_operations.get(planned.id)
    assert terminal_admin.state == "failed"
    assert terminal_admin.reason_codes == ("host.probe_unknown",)
    assert agent_operations.get(agent_operation_id) == persisted_agent
    assert isinstance(client.poll(poll), AgentNoWorkV1)
    assert admin_operations.get(planned.id) == terminal_admin
    assert agent_operations.get(agent_operation_id) == persisted_agent
    assert registry_document.read_bytes() == registry_before

    admin_operations.plan(
        kind="google.provision",
        generation=1,
        key="ordinary-prune-after-agent-ack",
        steps=("one",),
    )
    with pytest.raises(AdminOperationError, match="control.operation_not_found"):
        admin_operations.get(planned.id)

    admin_operations = AdminOperationStore(tmp_path, clock=clock)
    agent_operations = AgentOperationStore(tmp_path, clock=clock)
    client = InProcessAgentClient(
        AgentHttpApplication(
            agent_operations,
            RemoteHostProbeCompletionOwner(
                operation_store=admin_operations,
                agent_operations=agent_operations,
                host_registry=HostRegistry(tmp_path),
            ),
        ),
        HostRegistry(tmp_path),
        client_spki_sha256=SPKI_ONE,
    )
    assert isinstance(client.poll(poll), AgentNoWorkV1)
    with pytest.raises(AdminOperationError, match="control.operation_not_found"):
        admin_operations.get(planned.id)


def test_receipt_after_operation_deadline_is_rejected_before_registry_mutation(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    registry = HostRegistry(tmp_path)
    target = registry.provision_agent_binding(
        _registration("worker-one", "Worker One"),
        AgentBindingV1("worker-one", SPKI_ONE, 1, True),
        expected_generation=0,
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
        idempotency_key="receipt-after-operation-deadline",
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
    operation_deadline = agent_operations.get(
        next(
            record["operation_id"]
            for record in json.loads(
                (
                    tmp_path / "agent-operations" / "operations.json"
                ).read_text(encoding="utf-8")
            )["operations"]
        )
    ).deadline
    clock.now = operation_deadline - timedelta(seconds=1)
    poll = AgentPollV1(
        principal.registry_generation,
        principal.lease_epoch,
        CAPABILITIES_DIGEST,
        0,
    )
    lease = client.poll(poll)
    assert isinstance(lease, AgentLeaseV1)
    assert lease.deadline == operation_deadline
    receipt = _successful_probe_receipt(lease)
    registry_path = tmp_path / "admin-hosts" / "hosts.json"
    registry_before = registry_path.read_bytes()
    clock.now = operation_deadline + timedelta(seconds=1)

    with pytest.raises(HostAgentError, match="resource.host_response_invalid"):
        client.put_receipt(receipt)

    assert registry_path.read_bytes() == registry_before
    assert admin_operations.get(planned.id).state == "planned"
    assert agent_operations.get(lease.operation_id).state == "leased"
    assert isinstance(client.poll(poll), AgentNoWorkV1)
    assert admin_operations.get(planned.id).state == "failed"
    terminal = agent_operations.get(lease.operation_id)
    assert terminal.state == "unknown"
    assert terminal.reason_codes == ("host.lease_expired",)
    assert registry_path.read_bytes() == registry_before


def test_pruned_split_batch_retries_without_starving_later_or_other_host(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = MutableClock()
    registry = HostRegistry(tmp_path)
    first = registry.provision_agent_binding(
        _registration("worker-one", "Worker One"),
        AgentBindingV1("worker-one", SPKI_ONE, 1, True),
        expected_generation=0,
    )
    second = registry.provision_agent_binding(
        _registration("worker-two", "Worker Two"),
        AgentBindingV1("worker-two", SPKI_TWO, 1, True),
        expected_generation=1,
    )
    first_principal = registry.resolve_agent_spki(SPKI_ONE)
    second_principal = registry.resolve_agent_spki(SPKI_TWO)
    admin_operations = AdminOperationStore(tmp_path, clock=clock)
    agent_operations = AgentOperationStore(tmp_path, clock=clock)
    adapter = RemoteHostProbeAdapter(
        operation_store=admin_operations,
        agent_operations=agent_operations,
        host_registry=registry,
        clock=clock,
    )
    first_plans = [
        adapter.probe(
            "worker-one",
            expected_generation=first.generation,
            idempotency_key=f"bounded-pruned-split-{index}",
        )
        for index in range(10)
    ]
    second_plan = adapter.probe(
        "worker-two",
        expected_generation=second.generation,
        idempotency_key="bounded-pruned-split-other-host",
    )
    operation_path = tmp_path / "agent-operations" / "operations.json"
    operation_document = json.loads(operation_path.read_text(encoding="utf-8"))
    operation_ids = [
        record["operation_id"] for record in operation_document["operations"]
    ]
    clock.now = max(
        agent_operations.get(operation_id).deadline
        for operation_id in operation_ids
    )
    agent_operations.expire_leases()
    persisted_operations = json.loads(
        operation_path.read_text(encoding="utf-8")
    )["operations"]
    assert all(record["state"] == "unknown" for record in persisted_operations)
    clock.now = max(plan.expires_at for plan in (*first_plans, second_plan)) + timedelta(
        seconds=1
    )
    admin_operations.plan(
        kind="google.provision",
        generation=1,
        key="ordinary-capacity-prune-for-bounded-splits",
        steps=("one",),
    )
    assert all(admin_operations.get(plan.id).state == "planned" for plan in first_plans)
    assert admin_operations.get(second_plan.id).state == "planned"

    admin_operations = AdminOperationStore(tmp_path, clock=clock)
    agent_operations = AgentOperationStore(tmp_path, clock=clock)
    owner = RemoteHostProbeCompletionOwner(
        operation_store=admin_operations,
        agent_operations=agent_operations,
        host_registry=HostRegistry(tmp_path),
    )
    original_claim = admin_operations.claim_host_probe_agent
    failures = 0

    def fail_first_claim(*args: object, **kwargs: object) -> object:
        nonlocal failures
        failures += 1
        if failures == 1:
            raise AdminOperationError("control.operation_store_unavailable")
        return original_claim(*args, **kwargs)

    monkeypatch.setattr(
        admin_operations,
        "claim_host_probe_agent",
        fail_first_claim,
    )
    application = AgentHttpApplication(agent_operations, owner)
    first_client = InProcessAgentClient(
        application,
        HostRegistry(tmp_path),
        client_spki_sha256=SPKI_ONE,
    )
    second_client = InProcessAgentClient(
        application,
        HostRegistry(tmp_path),
        client_spki_sha256=SPKI_TWO,
    )
    first_poll = AgentPollV1(
        first_principal.registry_generation,
        first_principal.lease_epoch,
        CAPABILITIES_DIGEST,
        0,
    )
    second_poll = AgentPollV1(
        second_principal.registry_generation,
        second_principal.lease_epoch,
        CAPABILITIES_DIGEST,
        0,
    )

    with pytest.raises(HostAgentError, match="resource.host_response_invalid"):
        first_client.poll(first_poll)
    assert all(admin_operations.get(plan.id).state == "planned" for plan in first_plans)
    assert isinstance(first_client.poll(first_poll), AgentNoWorkV1)
    assert sum(admin_operations.get(plan.id).state == "failed" for plan in first_plans) == 8
    assert isinstance(first_client.poll(first_poll), AgentNoWorkV1)
    assert all(admin_operations.get(plan.id).state == "failed" for plan in first_plans)
    assert admin_operations.get(second_plan.id).state == "planned"
    assert isinstance(second_client.poll(second_poll), AgentNoWorkV1)
    assert admin_operations.get(second_plan.id).state == "failed"
    after_operations = json.loads(operation_path.read_text(encoding="utf-8"))
    assert after_operations["schema_version"] == 1
    assert after_operations["operations"] == persisted_operations
    lifecycle_path = tmp_path / "admin-operations" / "host-probe-lifecycle.json"
    lifecycle_bytes = lifecycle_path.read_bytes()
    lifecycle = json.loads(lifecycle_bytes)
    assert lifecycle["schema_version"] == 1
    assert len(lifecycle["owners"]) == 11
    assert all(owner_record["acknowledged"] for owner_record in lifecycle["owners"])
    assert len(lifecycle_bytes) <= 1024 * 1024

    admin_operations.plan(
        kind="google.provision",
        generation=1,
        key="ordinary-prune-after-bounded-split-acks",
        steps=("one",),
    )
    for plan in (*first_plans, second_plan):
        with pytest.raises(AdminOperationError, match="control.operation_not_found"):
            admin_operations.get(plan.id)

    admin_operations = AdminOperationStore(tmp_path, clock=clock)
    agent_operations = AgentOperationStore(tmp_path, clock=clock)
    restarted = InProcessAgentClient(
        AgentHttpApplication(
            agent_operations,
            RemoteHostProbeCompletionOwner(
                operation_store=admin_operations,
                agent_operations=agent_operations,
                host_registry=HostRegistry(tmp_path),
            ),
        ),
        HostRegistry(tmp_path),
        client_spki_sha256=SPKI_ONE,
    )
    assert isinstance(restarted.poll(first_poll), AgentNoWorkV1)
    assert isinstance(restarted.poll(first_poll), AgentNoWorkV1)


def test_queued_agent_deadline_terminalizes_without_lease_in_production_poll(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    registry = HostRegistry(tmp_path)
    target = registry.provision_agent_binding(
        _registration("worker-one", "Worker One"),
        AgentBindingV1("worker-one", SPKI_ONE, 1, True),
        expected_generation=0,
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
        idempotency_key="queued-production-agent-deadline",
    )
    operation_document = json.loads(
        (tmp_path / "agent-operations" / "operations.json").read_text(
            encoding="utf-8"
        )
    )
    agent_operation_id = operation_document["operations"][0]["operation_id"]
    operation_deadline = agent_operations.get(agent_operation_id).deadline
    clock.now = operation_deadline
    registry_path = tmp_path / "admin-hosts" / "hosts.json"
    registry_before = registry_path.read_bytes()
    client = InProcessAgentClient(
        AgentHttpApplication(
            agent_operations,
            RemoteHostProbeCompletionOwner(
                operation_store=admin_operations,
                agent_operations=agent_operations,
                host_registry=registry,
            ),
        ),
        registry,
        client_spki_sha256=SPKI_ONE,
    )

    result = client.poll(
        AgentPollV1(
            principal.registry_generation,
            principal.lease_epoch,
            CAPABILITIES_DIGEST,
            0,
        )
    )

    assert isinstance(result, AgentNoWorkV1)
    terminal_admin = admin_operations.get(planned.id)
    terminal_agent = agent_operations.get(agent_operation_id)
    assert terminal_admin.state == "failed"
    assert terminal_admin.reason_codes == ("host.probe_unknown",)
    assert terminal_agent.state == "unknown"
    assert terminal_agent.attempt == 0
    assert terminal_agent.lease_id is None
    assert terminal_agent.reason_codes == ("host.lease_expired",)
    lifecycle = json.loads(
        (
            tmp_path / "admin-operations" / "host-probe-lifecycle.json"
        ).read_text(encoding="utf-8")
    )
    assert lifecycle["schema_version"] == 1
    assert lifecycle["owners"][0]["acknowledged"] is True
    assert registry_path.read_bytes() == registry_before


@pytest.mark.parametrize(
    ("step_state", "step_reason", "expected_state", "expected_reason"),
    (
        ("not_attempted", None, "failed", "host.probe_unknown"),
        ("failed", "host.probe_unknown", "failed", "host.probe_unknown"),
        ("failed", "host.probe_failed", "failed", "host.probe_failed"),
        ("succeeded", None, "partial", "control.restart_reconciled"),
    ),
)
def test_expired_restart_reconciled_steps_converge_through_lifecycle_owner(
    tmp_path: Path,
    step_state: str,
    step_reason: str | None,
    expected_state: str,
    expected_reason: str,
) -> None:
    clock = MutableClock()
    dead_owner = DeadOwnerProbe()
    registry = HostRegistry(tmp_path)
    target = registry.provision_agent_binding(
        _registration("worker-one", "Worker One"),
        AgentBindingV1("worker-one", SPKI_ONE, 1, True),
        expected_generation=0,
    )
    principal = registry.resolve_agent_spki(SPKI_ONE)
    admin_operations = AdminOperationStore(
        tmp_path,
        clock=clock,
        owner_probe=dead_owner,
    )
    agent_operations = AgentOperationStore(tmp_path, clock=clock)
    planned = RemoteHostProbeAdapter(
        operation_store=admin_operations,
        agent_operations=agent_operations,
        host_registry=registry,
        clock=clock,
    ).probe(
        "worker-one",
        expected_generation=target.generation,
        idempotency_key=f"lifecycle-step-{step_state}-{step_reason}",
    )
    admin_operations.begin(
        planned.id,
        current_generation=target.generation,
    )
    if step_state != "not_attempted":
        admin_operations.record_step(
            planned.id,
            "host.probe.collect",
            succeeded=step_state == "succeeded",
            reason_code=step_reason,
        )
    operation_document = json.loads(
        (tmp_path / "agent-operations" / "operations.json").read_text(
            encoding="utf-8"
        )
    )
    agent_operation_id = operation_document["operations"][0]["operation_id"]
    clock.now = agent_operations.get(agent_operation_id).deadline
    agent_operations.expire_leases()
    persisted_agent = agent_operations.get(agent_operation_id)
    assert persisted_agent.state == "unknown"
    clock.now = planned.expires_at + timedelta(seconds=1)
    admin_operations = AdminOperationStore(
        tmp_path,
        clock=clock,
        owner_probe=dead_owner,
    )
    before = admin_operations.get(planned.id)
    assert before.state == "partial"
    assert before.reason_codes == ("control.restart_reconciled",)
    registry_path = tmp_path / "admin-hosts" / "hosts.json"
    registry_before = registry_path.read_bytes()

    def client_for(
        admin_store: AdminOperationStore,
        agent_store: AgentOperationStore,
    ) -> InProcessAgentClient:
        current_registry = HostRegistry(tmp_path)
        return InProcessAgentClient(
            AgentHttpApplication(
                agent_store,
                RemoteHostProbeCompletionOwner(
                    operation_store=admin_store,
                    agent_operations=agent_store,
                    host_registry=current_registry,
                ),
            ),
            current_registry,
            client_spki_sha256=SPKI_ONE,
        )

    poll = AgentPollV1(
        principal.registry_generation,
        principal.lease_epoch,
        CAPABILITIES_DIGEST,
        0,
    )
    client = client_for(admin_operations, agent_operations)
    assert isinstance(client.poll(poll), AgentNoWorkV1)
    terminal = admin_operations.get(planned.id)
    assert terminal.state == expected_state
    assert terminal.reason_codes == (expected_reason,)
    assert terminal.completed_count == (step_state == "succeeded")
    assert terminal.failed_count == (
        step_state == "failed" or step_state == "not_attempted"
    )
    assert agent_operations.get(agent_operation_id) == persisted_agent
    assert isinstance(client.poll(poll), AgentNoWorkV1)

    admin_operations = AdminOperationStore(
        tmp_path,
        clock=clock,
        owner_probe=dead_owner,
    )
    agent_operations = AgentOperationStore(tmp_path, clock=clock)
    assert isinstance(client_for(admin_operations, agent_operations).poll(poll), AgentNoWorkV1)
    assert admin_operations.get(planned.id) == terminal
    assert agent_operations.get(agent_operation_id) == persisted_agent
    assert registry_path.read_bytes() == registry_before


def test_agent_deadline_terminalizes_live_paired_admin_through_production_poll(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    registry = HostRegistry(tmp_path)
    target = registry.provision_agent_binding(
        _registration("worker-one", "Worker One"),
        AgentBindingV1("worker-one", SPKI_ONE, 1, True),
        expected_generation=0,
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
        idempotency_key="live-admin-agent-deadline",
    )
    client = InProcessAgentClient(
        AgentHttpApplication(
            agent_operations,
            RemoteHostProbeCompletionOwner(
                operation_store=admin_operations,
                agent_operations=agent_operations,
                host_registry=registry,
            ),
        ),
        registry,
        client_spki_sha256=SPKI_ONE,
    )
    poll = AgentPollV1(
        principal.registry_generation,
        principal.lease_epoch,
        CAPABILITIES_DIGEST,
        0,
    )
    lease = client.poll(poll)
    assert isinstance(lease, AgentLeaseV1)
    clock.advance(seconds=301)
    assert clock.now < planned.expires_at

    assert isinstance(client.poll(poll), AgentNoWorkV1)
    terminal_admin = admin_operations.get(planned.id)
    terminal_agent = agent_operations.get(lease.operation_id)
    assert terminal_admin.state == "failed"
    assert terminal_admin.reason_codes == ("host.probe_unknown",)
    assert terminal_agent.state == "unknown"
    assert terminal_agent.reason_codes == ("host.lease_expired",)
    assert isinstance(client.poll(poll), AgentNoWorkV1)
    assert admin_operations.get(planned.id) == terminal_admin
    assert agent_operations.get(lease.operation_id) == terminal_agent


def test_slow_eighth_lease_after_plan_lifetime_expires_through_production_poll(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    registry = HostRegistry(tmp_path)
    target = registry.provision_agent_binding(
        _registration("worker-one", "Worker One"),
        AgentBindingV1("worker-one", SPKI_ONE, 1, True),
        expected_generation=0,
    )
    principal = registry.resolve_agent_spki(SPKI_ONE)
    admin_operations = AdminOperationStore(tmp_path, clock=clock)
    agent_operations = AgentOperationStore(tmp_path, clock=clock)
    planned = admin_operations.plan(
        kind="hosts.probe",
        generation=target.generation,
        key="slow-eighth-lease-admin",
        steps=("host.probe.collect",),
    )
    queued = agent_operations.enqueue(
        AgentOperationRequestV1(
            key="slow-eighth-lease-agent",
            kind="host.probe",
            action="collect",
            registry_generation=registry.document_generation(),
            plan_digest=planned.plan_digest,
            arguments={
                "admin_operation_id": planned.operation_id,
                "probe_schema": 1,
            },
            deadline=clock.now + timedelta(minutes=15),
            target_host_ref="worker-one",
        )
    )
    client = InProcessAgentClient(
        AgentHttpApplication(
            agent_operations,
            RemoteHostProbeCompletionOwner(
                operation_store=admin_operations,
                agent_operations=agent_operations,
                host_registry=registry,
            ),
        ),
        registry,
        client_spki_sha256=SPKI_ONE,
    )
    poll = AgentPollV1(
        principal.registry_generation,
        principal.lease_epoch,
        CAPABILITIES_DIGEST,
        0,
    )
    for attempt in range(1, 9):
        lease = client.poll(poll)
        assert isinstance(lease, AgentLeaseV1)
        assert lease.attempt == attempt
        clock.advance(seconds=121)
    assert clock.now > planned.expires_at

    admin_operations = AdminOperationStore(tmp_path, clock=clock)
    agent_operations = AgentOperationStore(tmp_path, clock=clock)
    registry = HostRegistry(tmp_path)
    registry_document = tmp_path / "admin-hosts" / "hosts.json"
    registry_before = registry_document.read_bytes()
    terminal_order: list[str] = []
    agent_terminal_recorded = False
    original_write = agent_operations._write_locked

    def ordered_agent_write(document: object) -> None:
        nonlocal agent_terminal_recorded
        terminal_write = isinstance(document, dict) and any(
            isinstance(record, dict)
            and record.get("operation_id") == queued.operation_id
            and record.get("completion")
            == {
                "reason_codes": ["host.lease_expired"],
                "result_digest": None,
            }
            for record in document.get("operations", ())
        )
        if terminal_write and not agent_terminal_recorded:
            agent_terminal_recorded = True
            terminal_order.append(admin_operations.get(planned.operation_id).state)
        original_write(cast(dict[str, object], document))

    agent_operations._write_locked = ordered_agent_write  # type: ignore[method-assign]
    client = InProcessAgentClient(
        AgentHttpApplication(
            agent_operations,
            RemoteHostProbeCompletionOwner(
                operation_store=admin_operations,
                agent_operations=agent_operations,
                host_registry=registry,
            ),
        ),
        registry,
        client_spki_sha256=SPKI_ONE,
    )

    assert isinstance(client.poll(poll), AgentNoWorkV1)
    terminal_admin = admin_operations.get(planned.operation_id)
    terminal_agent = agent_operations.get(queued.operation_id)
    assert terminal_admin.state == "failed"
    assert terminal_admin.reason_codes == ("host.probe_unknown",)
    assert terminal_agent.state == "unknown"
    assert terminal_agent.reason_codes == ("host.lease_expired",)
    assert terminal_agent.attempt == 8
    assert terminal_order == ["failed"]
    assert isinstance(client.poll(poll), AgentNoWorkV1)
    assert admin_operations.get(planned.operation_id) == terminal_admin
    assert agent_operations.get(queued.operation_id) == terminal_agent
    assert registry_document.read_bytes() == registry_before
