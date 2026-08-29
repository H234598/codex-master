from __future__ import annotations

import json
from pathlib import Path
import sys

USAGE_SRC = Path(
    "/home/teladi/.codex-worktrees/codex-usage/google-control-ui-20260828/src"
)
sys.path.insert(0, str(USAGE_SRC))

from codex_usage.masterjet_client import _encode_request, _step_up_challenge  # noqa: E402
from codex_usage.masterjet_contracts import (  # noqa: E402
    parse_secret_ingress_receipt,
    parse_secret_ingress_session,
)

from codex_master.admin_contracts import parse_admin_request  # noqa: E402
from test_admin_http import (  # noqa: E402
    _headers,
    _request,
    _running_server,
    _totp,
)
from test_admin_service import service_at  # noqa: E402


def test_real_usage_mutation_requests_match_canonical_admin_parser() -> None:
    openai, _secret = _encode_request(
        "openai.auth.apply",
        {"account_ref": "openai-one"},
        expected_generation=4,
        idempotency_key="idem-openai",
        plan_digest="sha256:" + "a" * 64,
    )
    ingress, _secret = _encode_request(
        "secret.ingress.create",
        {
            "account_ref": "openai-one",
            "credential_kind": "openai.auth-json",
        },
        expected_generation=4,
        idempotency_key="idem-ingress",
        plan_digest="sha256:" + "a" * 64,
    )

    assert parse_admin_request(json.loads(openai)).operation == "openai.auth.apply"
    assert parse_admin_request(json.loads(ingress)).operation == "secret.ingress.create"


def test_real_usage_parser_accepts_canonical_admin_secret_session(tmp_path) -> None:
    problem = {
        "schema_version": 1,
        "code": "control.step_up_required",
        "severity": "warning",
        "title": "Step-up required",
        "detail": "Additional authentication is required.",
        "effect": "Operation is paused.",
        "action": "Complete step-up authentication.",
        "retryable": False,
        "retry_after_seconds": None,
        "correlation_id": "corr-one",
        "occurred_at": "2026-08-29T12:00:00Z",
    }
    assert _step_up_challenge((403, json.dumps(problem).encode()))
    service, _owners = service_at()
    create_body, _ = _encode_request(
        "secret.ingress.create",
        {"account_ref": "openai-one", "credential_kind": "openai.auth-json"},
        expected_generation=4,
        idempotency_key="idem-ingress",
        plan_digest="sha256:" + "a" * 64,
    )
    with _running_server(tmp_path, service=service) as (server, _service):
        created = _request(
            server,
            "POST",
            "/admin/v1",
            create_body,
            _headers(**{"X-Masterjet-Step-Up": _totp()}),
        )
        uploaded = _request(
            server,
            "PUT",
            "/admin/v1/secret-ingress-sessions/ingress-one",
            b"auth-json",
            _headers(**{"Content-Type": "application/octet-stream"}),
        )
    assert created[0] == uploaded[0] == 200
    session = parse_secret_ingress_session(json.loads(created[2]))
    receipt = parse_secret_ingress_receipt(json.loads(uploaded[2]))
    assert session.id == "ingress-one"
    assert receipt.session_id == "ingress-one"


def test_real_usage_secret_flow_uses_canonical_digest_binding(tmp_path) -> None:
    service, _owners = service_at()
    create_body, _ = _encode_request(
        "secret.ingress.create",
        {
            "account_ref": "google-one",
            "credential_kind": "google.oauth-client",
        },
        expected_generation=4,
        idempotency_key="idem-create",
        plan_digest="sha256:" + "a" * 64,
    )
    apply_body, _ = _encode_request(
        "google.oauth-client-import.apply",
        {"account_ref": "google-one"},
        expected_generation=4,
        idempotency_key="idem-apply",
        plan_digest="sha256:" + "a" * 64,
    )
    with _running_server(tmp_path, service=service) as (server, _service):
        created = _request(
            server,
            "POST",
            "/admin/v1",
            create_body,
            _headers(**{"X-Masterjet-Step-Up": _totp()}),
        )
        assert created[0] == 200
        uploaded = _request(
            server,
            "PUT",
            "/admin/v1/secret-ingress-sessions/ingress-one",
            b"oauth-client-json",
            _headers(**{"Content-Type": "application/octet-stream"}),
        )
        assert uploaded[0] == 200
        applied = _request(server, "POST", "/admin/v1", apply_body, _headers())
        assert applied[0] == 200


def test_real_usage_accounts_request_receives_server_bound_oauth_client_ref(
    tmp_path,
) -> None:
    service, _owners = service_at()
    body, _secret = _encode_request(
        "google.accounts.list",
        {},
        expected_generation=None,
        idempotency_key=None,
    )

    with _running_server(tmp_path, service=service) as (server, _service):
        status, _headers_out, payload = _request(
            server, "POST", "/admin/v1", body, _headers()
        )

    account = json.loads(payload)["accounts"][0]
    assert status == 200
    assert account["default_oauth_client_ref"] == "oauth-client-opaque"
    assert account["oauth_client_availability"] == "available"
    assert "client_id" not in account
    assert "client_secret" not in account
