from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from codex_master.admin_contracts import (
    AdminContractError,
    AdminRequestV1,
    OperationV1,
    parse_admin_request,
    public_admin_result,
)


def test_admin_request_requires_generation_and_idempotency_for_mutation() -> None:
    with pytest.raises(AdminContractError, match="control.request_invalid"):
        parse_admin_request({"schema_version": 1, "operation": "google.provision.apply"})


def test_public_result_rejects_secret_keys() -> None:
    with pytest.raises(AdminContractError, match="control.response_private"):
        public_admin_result({"secret": "never"})


def test_admin_request_rejects_unknown_fields() -> None:
    with pytest.raises(AdminContractError, match="control.request_invalid"):
        parse_admin_request(
            {
                "schema_version": 1,
                "operation": "google.accounts.list",
                "unknown": "value",
            }
        )


def test_admin_request_rejects_private_argument_keys() -> None:
    with pytest.raises(AdminContractError, match="control.request_invalid"):
        parse_admin_request(
            {
                "schema_version": 1,
                "operation": "google.accounts.list",
                "arguments": {"access_token": "never"},
            }
        )


def test_admin_request_accepts_major_one_query_with_bounded_arguments() -> None:
    request = parse_admin_request(
        {
            "schema_version": 1,
            "operation": "google.accounts.list",
            "arguments": {"labels": ["active", "oauth"]},
        }
    )

    assert request == AdminRequestV1(
        operation="google.accounts.list",
        arguments={"labels": ("active", "oauth")},
        expected_generation=None,
        idempotency_key=None,
    )


def test_admin_request_rejects_unsupported_schema_major() -> None:
    with pytest.raises(AdminContractError, match="control.request_invalid"):
        parse_admin_request({"schema_version": 2, "operation": "google.accounts.list"})


@pytest.mark.parametrize("private_value", [
    {"nested": {"authorization": "Bearer never"}},
    {"items": [{"cookie": "never"}]},
    {"auth_json": "never"},
    {"backend_account_id": "never"},
    {"location": "/private/internal/path"},
])
def test_public_result_rejects_recursive_private_values(private_value: dict[str, object]) -> None:
    with pytest.raises(AdminContractError, match="control.response_private"):
        public_admin_result(private_value)


def test_public_result_returns_detached_json_safe_projection() -> None:
    source = {"accounts": [{"ref": "google-one"}], "generation": 7}

    result = public_admin_result(source)
    source["accounts"][0]["ref"] = "changed"

    assert result == {"accounts": [{"ref": "google-one"}], "generation": 7}


def test_operation_contract_is_immutable() -> None:
    operation = OperationV1(
        operation_id="op-1",
        kind="google.provision",
        state="planned",
        expected_generation=4,
        resulting_generation=None,
        plan_digest="sha256:" + "a" * 64,
        reason_codes=("control.plan_ready",),
    )

    with pytest.raises(FrozenInstanceError):
        operation.state = "started"  # type: ignore[misc]
