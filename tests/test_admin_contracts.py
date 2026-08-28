from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta

import pytest

from codex_master.admin_contracts import (
    AdminContractError,
    AdminPrincipalV1,
    AdminRequestV1,
    HiveProblemV1,
    OperationV1,
    parse_admin_request,
    public_admin_result,
)


CREATED = datetime(2026, 8, 28, 10, 0, tzinfo=UTC)
EXPIRES = datetime(2026, 8, 28, 10, 15, tzinfo=UTC)
DIGEST = "sha256:" + "a" * 64


def operation(**changes: object) -> OperationV1:
    values: dict[str, object] = {
        "id": "op-1", "kind": "google.provision", "state": "planned",
        "expected_generation": 4, "resulting_generation": None, "plan_digest": DIGEST,
        "created_at": CREATED, "expires_at": EXPIRES, "completed_count": 0,
        "failed_count": 0, "not_attempted_count": 1, "reason_codes": ("control.plan_ready",),
    }
    values.update(changes)
    return OperationV1(**values)  # type: ignore[arg-type]


def problem(**changes: object) -> HiveProblemV1:
    values: dict[str, object] = {
        "code": "control.failed", "severity": "error", "title": "Request failed",
        "detail": "Retry with a new request", "effect": "Operation was not started",
        "action": "Review request", "retryable": True, "retry_after_seconds": 30,
        "correlation_id": "corr-1", "occurred_at": CREATED,
    }
    values.update(changes)
    return HiveProblemV1(**values)  # type: ignore[arg-type]


def test_admin_request_rejects_unknown_operation() -> None:
    with pytest.raises(AdminContractError, match="control.request_invalid"):
        parse_admin_request({"schema_version": 1, "operation": "google.provision.apply.v2"})


@pytest.mark.parametrize("value", [True, 2])
def test_admin_request_requires_exact_schema_major_one(value: object) -> None:
    with pytest.raises(AdminContractError, match="control.request_invalid"):
        parse_admin_request({"schema_version": value, "operation": "hosts.list"})


@pytest.mark.parametrize("missing", ["expected_generation", "idempotency_key", "plan_digest"])
def test_apply_requires_all_concurrency_fields(missing: str) -> None:
    request = {
        "schema_version": 1, "operation": "google.provision.apply",
        "arguments": {"account_ref": "google-one"}, "expected_generation": 4,
        "idempotency_key": "request-1", "plan_digest": DIGEST,
    }
    del request[missing]

    with pytest.raises(AdminContractError, match="control.request_invalid"):
        parse_admin_request(request)


@pytest.mark.parametrize(
    ("operation", "arguments"),
    [
        ("hosts.list", {"account_ref": "google-one"}),
        ("operations.get", {}),
        ("operations.get", {"operation_id": "op-1", "extra": "x"}),
        ("google.provision.plan", {"account_refs": ["google-one"]}),
        ("google.provision.plan", {"global_account_id": "all"}),
    ],
)
def test_operation_arguments_follow_exact_schema(operation: str, arguments: dict[str, object]) -> None:
    with pytest.raises(AdminContractError, match="control.request_invalid"):
        parse_admin_request({"schema_version": 1, "operation": operation, "arguments": arguments})


def test_parse_request_freezes_arguments() -> None:
    request = parse_admin_request(
        {
            "schema_version": 1, "operation": "google.provision.apply",
            "arguments": {"account_ref": "google-one"}, "expected_generation": 4,
            "idempotency_key": "request-1", "plan_digest": DIGEST,
        }
    )

    with pytest.raises(TypeError):
        request.arguments["account_ref"] = "changed"  # type: ignore[index]


def test_direct_request_constructor_validates() -> None:
    with pytest.raises(AdminContractError, match="control.request_invalid"):
        AdminRequestV1("hosts.list", {"unexpected": "value"}, None, None, None)


def test_operation_wire_matches_spec_fixture() -> None:
    assert public_admin_result(operation()) == {
        "schema_version": 1, "id": "op-1", "kind": "google.provision", "state": "planned",
        "expected_generation": 4, "resulting_generation": None, "plan_digest": DIGEST,
        "created_at": "2026-08-28T10:00:00Z", "expires_at": "2026-08-28T10:15:00Z",
        "completed_count": 0, "failed_count": 0, "not_attempted_count": 1,
        "reason_codes": ["control.plan_ready"],
    }


@pytest.mark.parametrize("state", ["pending", "PLANNED"])
def test_operation_rejects_unknown_state(state: str) -> None:
    with pytest.raises(AdminContractError, match="control.response_private"):
        operation(state=state)


@pytest.mark.parametrize(
    "changes",
    [
        {"created_at": datetime(2026, 8, 28, 10, 0)},
        {"expires_at": CREATED},
        {"expires_at": CREATED + timedelta(days=2)},
        {"completed_count": -1},
        {"failed_count": True},
        {"not_attempted_count": 100_001},
    ],
)
def test_operation_rejects_invalid_time_and_counts(changes: dict[str, object]) -> None:
    with pytest.raises(AdminContractError, match="control.response_private"):
        operation(**changes)


def test_problem_wire_matches_spec_fixture() -> None:
    assert public_admin_result(problem()) == {
        "schema_version": 1, "code": "control.failed", "severity": "error",
        "title": "Request failed", "detail": "Retry with a new request",
        "effect": "Operation was not started", "action": "Review request",
        "retryable": True, "retry_after_seconds": 30, "correlation_id": "corr-1",
        "occurred_at": "2026-08-28T10:00:00Z",
    }


@pytest.mark.parametrize("text", [
    "access_token=never", "cookie=session-secret", "Basic never", "eyJhbGciOiJIUzI1NiJ9.payload.sig",
    "sk-verysecretkey", "AIzaSyD012345678901234567890",
    "refresh_token=never", "clientSecret=never", "password never",
    "client.secret=never", "refresh-token=never", "client secret never",
    "apiKey=never", "failed at \"/private/auth.json\"", r"\\server\share\auth.json",
    "error [/home/x]", r"\Windows\private", r"\private\auth.json",
    "file:///private/auth.json", "bad\x1b[31mtext", "token rejected",
])
def test_problem_rejects_secret_path_and_control_text(text: str) -> None:
    with pytest.raises(AdminContractError, match="control.response_private"):
        problem(detail=text)


def test_problem_rejects_invalid_severity_and_retry_contract() -> None:
    with pytest.raises(AdminContractError, match="control.response_private"):
        problem(severity="fatal")
    with pytest.raises(AdminContractError, match="control.response_private"):
        problem(retryable=False, retry_after_seconds=1)


def test_dto_construction_is_deeply_immutable() -> None:
    value = operation()

    with pytest.raises(FrozenInstanceError):
        value.state = "running"  # type: ignore[misc]


def test_public_result_accepts_only_known_dtos() -> None:
    with pytest.raises(AdminContractError, match="control.response_private"):
        public_admin_result({"apiKey": "never"})


def test_principal_wire_has_schema_version() -> None:
    principal = AdminPrincipalV1("user-1", ("fleet.read",), "unix_peer", False)

    assert public_admin_result(principal)["schema_version"] == 1
