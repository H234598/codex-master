from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta

import pytest

from codex_master.admin_contracts import (
    ADMIN_OPERATION_METADATA,
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
        "id": "op-1",
        "kind": "google.provision",
        "state": "planned",
        "expected_generation": 4,
        "resulting_generation": None,
        "plan_digest": DIGEST,
        "created_at": CREATED,
        "expires_at": EXPIRES,
        "completed_count": 0,
        "failed_count": 0,
        "not_attempted_count": 1,
        "reason_codes": ("control.plan_ready",),
    }
    values.update(changes)
    return OperationV1(**values)  # type: ignore[arg-type]


def problem(**changes: object) -> HiveProblemV1:
    values: dict[str, object] = {
        "code": "control.failed",
        "severity": "error",
        "title": "Request failed",
        "detail": "Retry with a new request",
        "effect": "Operation was not started",
        "action": "Review request",
        "retryable": True,
        "retry_after_seconds": 30,
        "correlation_id": "corr-1",
        "occurred_at": CREATED,
    }
    values.update(changes)
    return HiveProblemV1(**values)  # type: ignore[arg-type]


def test_admin_request_rejects_unknown_operation() -> None:
    with pytest.raises(AdminContractError, match="control.request_invalid"):
        parse_admin_request(
            {"schema_version": 1, "operation": "google.provision.apply.v2"}
        )


@pytest.mark.parametrize(
    ("operation", "arguments", "scope"),
    (
        (
            "openai.accounts.add",
            {"account_ref": "openai-two", "label": "OpenAI Two"},
            "fleet.openai.write",
        ),
        (
            "openai.accounts.disable",
            {"account_ref": "openai-one"},
            "fleet.openai.write",
        ),
        (
            "google.accounts.add",
            {"account_ref": "google-two", "label": "Google Two"},
            "fleet.google.oauth",
        ),
    ),
)
def test_account_commands_are_canonical_generation_checked_operations(
    operation: str, arguments: dict[str, object], scope: str
) -> None:
    request = AdminRequestV1(operation, arguments, 4, "account-change", None)

    assert request.operation == operation
    assert request.arguments == arguments
    assert ADMIN_OPERATION_METADATA[operation].scope == scope
    assert ADMIN_OPERATION_METADATA[operation].command is True


def test_operation_metadata_is_immutable_and_owns_scope_and_fields() -> None:
    metadata = ADMIN_OPERATION_METADATA["google.provision.apply"]

    assert metadata.scope == "fleet.google.provision"
    assert metadata.argument_fields == ("account_ref",)
    assert metadata.requires_idempotency is True
    assert metadata.requires_digest is True
    with pytest.raises(TypeError):
        ADMIN_OPERATION_METADATA["google.provision.apply"] = metadata  # type: ignore[index]


@pytest.mark.parametrize("value", [True, 2])
def test_admin_request_requires_exact_schema_major_one(value: object) -> None:
    with pytest.raises(AdminContractError, match="control.request_invalid"):
        parse_admin_request({"schema_version": value, "operation": "hosts.list"})


@pytest.mark.parametrize(
    "missing", ["expected_generation", "idempotency_key", "plan_digest"]
)
def test_apply_requires_all_concurrency_fields(missing: str) -> None:
    request = {
        "schema_version": 1,
        "operation": "google.provision.apply",
        "arguments": {"account_ref": "google-one"},
        "expected_generation": 4,
        "idempotency_key": "request-1",
        "plan_digest": DIGEST,
    }
    del request[missing]

    with pytest.raises(AdminContractError, match="control.request_invalid"):
        parse_admin_request(request)


@pytest.mark.parametrize(
    ("operation", "arguments", "requires_digest"),
    [
        ("openai.auth.plan", {"account_ref": "openai-one"}, False),
        (
            "secret.ingress.create",
            {"account_ref": "openai-one", "credential_kind": "openai.auth-json"},
            True,
        ),
        (
            "google.oauth.begin",
            {
                "account_ref": "google-one",
                "oauth_client_ref": "client-one",
                "redirect_uri": "http://127.0.0.1/callback",
                "scope_profile": "inventory_readonly",
            },
            False,
        ),
        ("google.oauth-client-import.plan", {"account_ref": "google-one"}, False),
        ("google.oauth-client-import.apply", {"account_ref": "google-one"}, True),
        ("google.inventory.refresh", {}, False),
        ("google.provision.plan", {"account_ref": "google-one"}, False),
        (
            "google.billing.plan",
            {
                "account_ref": "google-one",
                "project_ref": "project-one",
                "billing_ref": "billing-one",
            },
            False,
        ),
        (
            "google.billing.apply",
            {
                "account_ref": "google-one",
                "project_ref": "project-one",
                "billing_ref": "billing-one",
                "plan_id": "billing-plan-one",
            },
            True,
        ),
    ],
)
def test_command_contracts_require_generation_idempotency_and_optional_digest(
    operation: str, arguments: dict[str, object], requires_digest: bool
) -> None:
    wire: dict[str, object] = {
        "schema_version": 1,
        "operation": operation,
        "arguments": arguments,
        "expected_generation": 4,
        "idempotency_key": "request-one",
    }
    if requires_digest:
        wire["plan_digest"] = DIGEST

    request = parse_admin_request(wire)

    assert request.operation == operation
    assert request.expected_generation == 4
    assert request.idempotency_key == "request-one"
    assert request.plan_digest == (DIGEST if requires_digest else None)


def test_operations_get_is_account_bound() -> None:
    request = parse_admin_request(
        {
            "schema_version": 1,
            "operation": "operations.get",
            "arguments": {"account_ref": "google-one", "operation_id": "op-one"},
        }
    )

    assert dict(request.arguments) == {
        "account_ref": "google-one",
        "operation_id": "op-one",
    }


def test_oauth_complete_uses_transaction_generation_without_shadow_replay_fields() -> (
    None
):
    request = parse_admin_request(
        {
            "schema_version": 1,
            "operation": "google.oauth.complete",
            "arguments": {
                "account_ref": "google-one",
                "transaction_id": "transaction-one",
                "redirect_uri": "http://127.0.0.1/callback",
                "state": "state-one",
            },
            "expected_generation": 4,
        }
    )

    assert request.expected_generation == 4
    assert request.idempotency_key is None
    assert request.plan_digest is None


def test_redirect_uri_uses_exact_utf8_byte_limit() -> None:
    prefix = "http://127.0.0.1/callback?state="
    exact = prefix + "a" * (4096 - len(prefix.encode("utf-8")))
    multibyte_oversized = prefix + "ä" * 2048

    request = AdminRequestV1(
        "google.oauth.begin",
        {
            "account_ref": "google-one",
            "oauth_client_ref": "client-one",
            "redirect_uri": exact,
            "scope_profile": "inventory_readonly",
        },
        4,
        "request-one",
        None,
    )

    assert request.arguments["redirect_uri"] == exact
    assert len(exact.encode("utf-8")) == 4096
    for redirect_uri in (exact + "a", multibyte_oversized):
        with pytest.raises(AdminContractError, match="control.request_invalid"):
            AdminRequestV1(
                "google.oauth.begin",
                {
                    "account_ref": "google-one",
                    "oauth_client_ref": "client-one",
                    "redirect_uri": redirect_uri,
                    "scope_profile": "inventory_readonly",
                },
                4,
                "request-two",
                None,
            )


@pytest.mark.parametrize("credential_kind", ["openai.auth-json", "google.oauth-client"])
def test_secret_ingress_accepts_only_closed_v1_credential_kinds(
    credential_kind: str,
) -> None:
    request = parse_admin_request(
        {
            "schema_version": 1,
            "operation": "secret.ingress.create",
            "arguments": {
                "account_ref": "google-one",
                "credential_kind": credential_kind,
            },
            "expected_generation": 4,
            "idempotency_key": "request-one",
            "plan_digest": DIGEST,
        }
    )

    assert request.arguments["credential_kind"] == credential_kind


def test_secret_ingress_rejects_unknown_credential_kind() -> None:
    with pytest.raises(AdminContractError, match="control.request_invalid"):
        parse_admin_request(
            {
                "schema_version": 1,
                "operation": "secret.ingress.create",
                "arguments": {
                    "account_ref": "google-one",
                    "credential_kind": "future.secret-format",
                },
                "expected_generation": 4,
                "idempotency_key": "request-one",
                "plan_digest": DIGEST,
            }
        )


@pytest.mark.parametrize(
    "operation",
    [
        "openai.auth.plan",
        "secret.ingress.create",
        "google.oauth.begin",
        "google.oauth-client-import.plan",
        "google.oauth-client-import.apply",
        "google.inventory.refresh",
        "google.provision.plan",
        "google.billing.plan",
    ],
)
def test_commands_reject_missing_concurrency_fields(operation: str) -> None:
    with pytest.raises(AdminContractError, match="control.request_invalid"):
        parse_admin_request(
            {
                "schema_version": 1,
                "operation": operation,
                "arguments": _valid_command_arguments(operation),
            }
        )


def _valid_command_arguments(operation: str) -> dict[str, object]:
    if operation == "secret.ingress.create":
        return {"account_ref": "openai-one", "credential_kind": "openai.auth-json"}
    if operation == "google.oauth.begin":
        return {
            "account_ref": "google-one",
            "oauth_client_ref": "client-one",
            "redirect_uri": "http://127.0.0.1/callback",
            "scope_profile": "inventory_readonly",
        }
    if operation == "google.oauth.complete":
        return {
            "account_ref": "google-one",
            "transaction_id": "transaction-one",
            "redirect_uri": "http://127.0.0.1/callback",
            "state": "state-one",
        }
    if operation == "google.billing.plan":
        return {
            "account_ref": "google-one",
            "project_ref": "project-one",
            "billing_ref": "billing-one",
        }
    if operation == "google.inventory.refresh":
        return {}
    return {"account_ref": "google-one"}


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
def test_operation_arguments_follow_exact_schema(
    operation: str, arguments: dict[str, object]
) -> None:
    with pytest.raises(AdminContractError, match="control.request_invalid"):
        parse_admin_request(
            {"schema_version": 1, "operation": operation, "arguments": arguments}
        )


def test_parse_request_freezes_arguments() -> None:
    request = parse_admin_request(
        {
            "schema_version": 1,
            "operation": "google.provision.apply",
            "arguments": {"account_ref": "google-one"},
            "expected_generation": 4,
            "idempotency_key": "request-1",
            "plan_digest": DIGEST,
        }
    )

    with pytest.raises(TypeError):
        request.arguments["account_ref"] = "changed"  # type: ignore[index]


def test_direct_request_constructor_validates() -> None:
    with pytest.raises(AdminContractError, match="control.request_invalid"):
        AdminRequestV1("hosts.list", {"unexpected": "value"}, None, None, None)


def test_operation_wire_matches_spec_fixture() -> None:
    assert public_admin_result(operation()) == {
        "schema_version": 1,
        "id": "op-1",
        "kind": "google.provision",
        "state": "planned",
        "expected_generation": 4,
        "resulting_generation": None,
        "plan_digest": DIGEST,
        "created_at": "2026-08-28T10:00:00Z",
        "expires_at": "2026-08-28T10:15:00Z",
        "completed_count": 0,
        "failed_count": 0,
        "not_attempted_count": 1,
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
        "schema_version": 1,
        "code": "control.failed",
        "severity": "error",
        "title": "Request failed",
        "detail": "Retry with a new request",
        "effect": "Operation was not started",
        "action": "Review request",
        "retryable": True,
        "retry_after_seconds": 30,
        "correlation_id": "corr-1",
        "occurred_at": "2026-08-28T10:00:00Z",
    }


@pytest.mark.parametrize(
    "text",
    [
        "access_token=never",
        "cookie=session-secret",
        "Basic never",
        "eyJhbGciOiJIUzI1NiJ9.payload.sig",
        "sk-verysecretkey",
        "AIzaSyD012345678901234567890",
        "refresh_token=never",
        "clientSecret=never",
        "password never",
        "client.secret=never",
        "refresh-token=never",
        "client secret never",
        "apiKey=never",
        'failed at "/private/auth.json"',
        r"\\server\share\auth.json",
        "error [/home/x]",
        r"\Windows\private",
        r"\private\auth.json",
        "file:///private/auth.json",
        "bad\x1b[31mtext",
        "token rejected",
    ],
)
def test_problem_rejects_secret_path_and_control_text(text: str) -> None:
    with pytest.raises(AdminContractError, match="control.response_private"):
        problem(detail=text)


@pytest.mark.parametrize(
    "text", ["client_secret=never", r"\secret.txt", r"\report.txt"]
)
def test_public_problem_projection_rejects_exact_adversarial_text(text: str) -> None:
    with pytest.raises(AdminContractError, match="control.response_private"):
        public_admin_result(problem(detail=text))


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
