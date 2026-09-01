from __future__ import annotations

import json
import hashlib
import os
from datetime import UTC, datetime, timedelta

import pytest

from codex_master.admin_hosts import AgentBindingV1, AgentPrincipalV1, HostRegistry
from codex_master.agent_contracts import (
    AgentLeaseV1,
    AgentNoWorkV1,
    AgentReceiptV1,
    AgentResultV1,
    serialize_agent_result,
)
from codex_master.agent_http import AgentHttpApplication
from codex_master.agent_operations import (
    AgentOperationError,
    AgentOperationRequestV1,
    AgentOperationStore,
    AgentPrincipalV1 as OperationPrincipalV1,
)


DIGEST = "sha256:" + "1" * 64


def principal() -> AgentPrincipalV1:
    return AgentPrincipalV1("worker-one", 7, 3)


def poll_bytes(**changes: object) -> bytes:
    document: dict[str, object] = {
        "schema_version": 1,
        "registry_generation": 7,
        "lease_epoch": 3,
        "capabilities_digest": DIGEST,
        "max_wait_seconds": 0,
    }
    document.update(changes)
    return json.dumps(document).encode()


def receipt_bytes(operation_id: str = "operation-one") -> bytes:
    result = {"kind": "host.probe", "action": "collect", "payload": {"reachable": True}}
    result_digest = "sha256:" + hashlib.sha256(
        json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return json.dumps(
        {
            "schema_version": 1,
            "operation_id": operation_id,
            "lease_id": "lease-one",
            "lease_epoch": 3,
            "attempt": 1,
            "plan_digest": DIGEST,
            "arguments_digest": DIGEST,
            "state": "succeeded",
            "reason_codes": ["host.completed"],
            "result_digest": result_digest,
            "result": result,
        }
    ).encode()


class Store:
    def __init__(self) -> None:
        self.poll_calls: list[object] = []
        self.complete_calls: list[object] = []
        self.failure: str | None = None

    def poll(self, principal_value, poll):
        self.poll_calls.append((principal_value, poll))
        if self.failure:
            raise AgentOperationError(self.failure)
        return AgentNoWorkV1(7, 3, 0)

    def complete(self, principal_value, receipt):
        self.complete_calls.append((principal_value, receipt))
        if self.failure:
            raise AgentOperationError(self.failure)
        return object()


@pytest.fixture
def store() -> Store:
    return Store()


@pytest.fixture
def app(store: Store) -> AgentHttpApplication:
    return AgentHttpApplication(store)


def test_agent_api_exposes_only_poll_and_receipt_routes(app) -> None:
    assert app.handle(principal(), "POST", "/agent/v1/polls", poll_bytes()).status == 200
    assert app.handle(principal(), "POST", "/admin/v1/hosts", b"{}").status == 404
    assert app.handle(principal(), "GET", "/agent/v1/polls", b"").status == 405
    assert app.handle(principal(), "POST", "/agent/v1/operations//receipts", b"{}").status == 404
    assert app.handle(principal(), "POST", "/agent/v1/operations/" + "a" * 129 + "/receipts", b"{}").status == 404


def test_poll_reuses_task_one_parser_and_projects_bounded_no_work(app, store) -> None:
    response = app.handle(principal(), "POST", "/agent/v1/polls", poll_bytes())
    assert response.status == 200
    assert response.headers == (("Content-Type", "application/json"), ("Cache-Control", "no-store"))
    assert json.loads(response.body) == {
        "schema_version": 1,
        "registry_generation": 7,
        "lease_epoch": 3,
        "max_wait_seconds": 0,
    }
    assert len(store.poll_calls) == 1
    assert type(store.poll_calls[0][0]) is OperationPrincipalV1


def test_admin_owned_shared_binding_reaches_real_api_poll_with_authoritative_fences(
    tmp_path,
) -> None:
    shared = tmp_path / "agent-state"
    shared.mkdir(mode=0o770)
    os.chmod(shared, 0o2770)
    admin_registry = HostRegistry(shared, shared_gid=os.getegid())
    spki = "sha256:" + "a" * 64
    admin_registry.provision_agent_binding(
        {
            "ref": "worker-one",
            "label": "Worker One",
            "role": "execution",
            "capabilities": ["resource.probe"],
        },
        AgentBindingV1("worker-one", spki, 1, True),
        expected_generation=0,
    )
    resolver_principal = HostRegistry(
        shared, shared_gid=os.getegid()
    ).resolve_agent_spki(spki)
    admin_store = AgentOperationStore(shared, shared_gid=os.getegid())
    admin_store.enqueue(
        AgentOperationRequestV1(
            key="http-real-store",
            kind="host.probe",
            action="collect",
            registry_generation=resolver_principal.registry_generation,
            plan_digest=DIGEST,
            arguments={"admin_operation_id": "op-one", "probe_schema": 1},
            deadline=datetime.now(UTC).replace(microsecond=0) + timedelta(minutes=5),
            target_host_ref="worker-one",
        )
    )
    store = AgentOperationStore(shared, shared_gid=os.getegid())
    application = AgentHttpApplication(store)

    response = application.handle(
        resolver_principal,
        "POST",
        "/agent/v1/polls",
        poll_bytes(registry_generation=0, lease_epoch=1),
    )

    assert response.status == 200
    lease_document = json.loads(response.body)
    assert lease_document["host_ref"] == "worker-one"
    deadline = datetime.strptime(
        lease_document["deadline"], "%Y-%m-%dT%H:%M:%SZ"
    ).replace(tzinfo=UTC)
    lease = AgentLeaseV1(
        deadline=deadline,
        **{
            key: value
            for key, value in lease_document.items()
            if key not in {"schema_version", "deadline"}
        },
    )
    result = AgentResultV1(
        "host.probe",
        "collect",
        {"status": "collected"},
    )
    result_digest = "sha256:" + hashlib.sha256(
        json.dumps(
            serialize_agent_result(result),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    receipt = AgentReceiptV1(
        lease.operation_id,
        lease.lease_id,
        lease.lease_epoch,
        lease.attempt,
        lease.plan_digest,
        lease.arguments_digest,
        "succeeded",
        ("host.completed",),
        result_digest,
        result,
    )
    receipt_response = application.handle(
        resolver_principal,
        "POST",
        f"/agent/v1/operations/{lease.operation_id}/receipts",
        json.dumps(
            {
                "schema_version": 1,
                "operation_id": receipt.operation_id,
                "lease_id": receipt.lease_id,
                "lease_epoch": receipt.lease_epoch,
                "attempt": receipt.attempt,
                "plan_digest": receipt.plan_digest,
                "arguments_digest": receipt.arguments_digest,
                "state": receipt.state,
                "reason_codes": list(receipt.reason_codes),
                "result_digest": receipt.result_digest,
                "result": serialize_agent_result(receipt.result),
            }
        ).encode(),
    )
    assert receipt_response.status == 200
    assert store.get(lease.operation_id).state == "succeeded"
    stale_epoch = application.handle(
        resolver_principal,
        "POST",
        "/agent/v1/polls",
        poll_bytes(registry_generation=1, lease_epoch=0),
    )
    assert stale_epoch.status == 409


def test_receipt_route_binds_path_to_task_one_receipt_before_completion(app, store) -> None:
    response = app.handle(
        principal(),
        "POST",
        "/agent/v1/operations/operation-one/receipts",
        receipt_bytes(),
    )
    assert response.status == 200
    assert len(store.complete_calls) == 1


def test_host_probe_receipt_uses_task_specific_completion_owner(store) -> None:
    calls: list[object] = []

    class Owner:
        def complete(self, principal_value, receipt) -> None:
            calls.append((principal_value, receipt))

    app = AgentHttpApplication(store, Owner())
    response = app.handle(
        principal(), "POST", "/agent/v1/operations/operation-one/receipts", receipt_bytes()
    )

    assert response.status == 200
    assert len(calls) == 1
    assert store.complete_calls == []
    mismatch = app.handle(
        principal(),
        "POST",
        "/agent/v1/operations/operation-two/receipts",
        receipt_bytes(),
    )
    assert mismatch.status == 400
    assert len(store.complete_calls) == 0


@pytest.mark.parametrize(
    "body",
    [b"", b"[]", b'{"schema_version":1}', b'{"schema_version":1,"schema_version":1}'],
)
def test_malformed_poll_is_deterministic_and_never_touches_store(app, store, body) -> None:
    response = app.handle(principal(), "POST", "/agent/v1/polls", body)
    assert response.status == 400
    assert json.loads(response.body) == {"error": "agent.request_invalid"}
    assert store.poll_calls == []


@pytest.mark.parametrize(
    ("code", "status"),
    [
        ("host.poll_already_active", 409),
        ("host.registry_generation_stale", 409),
        ("host.lease_epoch_stale", 409),
        ("host.operation_store_unavailable", 503),
        ("private.secret.detail", 400),
    ],
)
def test_store_errors_are_sanitized(app, store, code, status) -> None:
    store.failure = code
    response = app.handle(principal(), "POST", "/agent/v1/polls", poll_bytes())
    assert response.status == status
    assert len(response.body) < 128
    assert b"private" not in response.body
