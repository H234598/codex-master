from __future__ import annotations

import json
import hashlib

import pytest

from codex_master.admin_hosts import AgentPrincipalV1
from codex_master.agent_contracts import AgentNoWorkV1
from codex_master.agent_http import AgentHttpApplication
from codex_master.agent_operations import AgentOperationError


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


def test_receipt_route_binds_path_to_task_one_receipt_before_completion(app, store) -> None:
    response = app.handle(
        principal(),
        "POST",
        "/agent/v1/operations/operation-one/receipts",
        receipt_bytes(),
    )
    assert response.status == 200
    assert len(store.complete_calls) == 1
    mismatch = app.handle(
        principal(),
        "POST",
        "/agent/v1/operations/operation-two/receipts",
        receipt_bytes(),
    )
    assert mismatch.status == 400
    assert len(store.complete_calls) == 1


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
