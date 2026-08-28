from __future__ import annotations

from dataclasses import FrozenInstanceError
import math

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
        "schema_version": 1,
        "operation": "google.provision.apply",
        "arguments": {"account_ref": "google-one"},
        "expected_generation": 4,
        "idempotency_key": "request-1",
        "plan_digest": "sha256:" + "a" * 64,
    }
    del request[missing]

    with pytest.raises(AdminContractError, match="control.request_invalid"):
        parse_admin_request(request)


def test_non_apply_rejects_concurrency_fields() -> None:
    with pytest.raises(AdminContractError, match="control.request_invalid"):
        parse_admin_request(
            {
                "schema_version": 1,
                "operation": "google.provision.plan",
                "arguments": {"account_ref": "google-one"},
                "expected_generation": 4,
            }
        )


@pytest.mark.parametrize(
    ("operation", "arguments"),
    [
        ("hosts.list", {"account_ref": "google-one"}),
        ("operations.get", {}),
        ("operations.get", {"operation_id": "op-1", "extra": "x"}),
        ("google.provision.plan", {}),
        ("google.provision.plan", {"account_refs": ["google-one"]}),
        ("google.provision.plan", {"global_account_id": "all"}),
    ],
)
def test_operation_arguments_follow_exact_schema(operation: str, arguments: dict[str, object]) -> None:
    with pytest.raises(AdminContractError, match="control.request_invalid"):
        parse_admin_request({"schema_version": 1, "operation": operation, "arguments": arguments})


def test_parse_request_freezes_nested_arguments() -> None:
    request = parse_admin_request(
        {
            "schema_version": 1,
            "operation": "google.provision.apply",
            "arguments": {"account_ref": "google-one"},
            "expected_generation": 4,
            "idempotency_key": "request-1",
            "plan_digest": "sha256:" + "a" * 64,
        }
    )

    with pytest.raises(TypeError):
        request.arguments["account_ref"] = "changed"  # type: ignore[index]


def test_direct_request_constructor_validates_and_freezes() -> None:
    with pytest.raises(AdminContractError, match="control.request_invalid"):
        AdminRequestV1("hosts.list", {"unexpected": "value"}, None, None, None)


def test_direct_operation_rejects_boolean_generation() -> None:
    with pytest.raises(AdminContractError, match="control.response_private"):
        OperationV1("op-1", "google.provision", "planned", True, None, "sha256:" + "a" * 64, ())


def test_direct_operation_rejects_unbounded_generation() -> None:
    with pytest.raises(AdminContractError, match="control.response_private"):
        OperationV1("op-1", "google.provision", "planned", 2**63, None, "sha256:" + "a" * 64, ())


def test_public_result_accepts_only_known_dtos() -> None:
    with pytest.raises(AdminContractError, match="control.response_private"):
        public_admin_result({"apiKey": "never"})


@pytest.mark.parametrize("private_text", [
    "Bearer never",
    "file:///private/auth.json",
    r"\\server\share\auth.json",
    "message: /private/auth.json",
])
def test_public_error_rejects_secret_or_path_text(private_text: str) -> None:
    with pytest.raises(AdminContractError, match="control.response_private"):
        HiveProblemV1("control.failed", private_text, {})


def test_public_problem_has_explicit_v1_wire_form() -> None:
    problem = HiveProblemV1("control.failed", "request failed", {"reason_codes": ["control.denied"]})

    assert public_admin_result(problem) == {
        "schema_version": 1,
        "code": "control.failed",
        "message": "request failed",
        "details": {"reason_codes": ["control.denied"]},
    }


def test_public_operation_and_principal_have_explicit_v1_wire_forms() -> None:
    operation = OperationV1("op-1", "google.provision", "planned", 4, None, "sha256:" + "a" * 64, ("control.plan_ready",))
    principal = AdminPrincipalV1("user-1", ("fleet.read",), "unix_peer", False)

    assert public_admin_result(operation)["schema_version"] == 1
    assert public_admin_result(principal)["schema_version"] == 1


def test_dto_construction_is_deeply_immutable_and_validated() -> None:
    problem = HiveProblemV1("control.failed", "request failed", {"reason_codes": ["control.denied"]})

    with pytest.raises(TypeError):
        problem.details["reason_codes"] = ()  # type: ignore[index]
    with pytest.raises(FrozenInstanceError):
        problem.code = "control.changed"  # type: ignore[misc]
    with pytest.raises(AdminContractError, match="control.response_private"):
        HiveProblemV1("control.failed", "request failed", {"passphrase": "never"})
    with pytest.raises(AdminContractError, match="control.response_private"):
        HiveProblemV1("control.failed", "request failed", {"value": math.nan})
