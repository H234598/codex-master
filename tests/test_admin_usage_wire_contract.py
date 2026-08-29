from __future__ import annotations

import json
from pathlib import Path
import sys


USAGE_SRC = Path(
    "/home/teladi/.codex-worktrees/codex-usage/google-control-ui-20260828/src"
)
sys.path.insert(0, str(USAGE_SRC))

from codex_usage.masterjet_client import _encode_request, _step_up_challenge  # noqa: E402
from codex_usage.masterjet_client import _decode_response  # noqa: E402
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


def test_real_usage_openai_and_ingress_requests_normalize_to_admin_request_v1() -> None:
    openai, _secret = _encode_request(
        "openai.auth-sync.apply",
        {"account_ref": "openai-one", "plan_id": "plan-one"},
        expected_generation=4,
        idempotency_key="idem-openai",
    )
    ingress, _secret = _encode_request(
        "secret.ingress.create",
        {
            "account_ref": "openai-one",
            "credential_type": "openai.auth-json",
            "plan_id": "plan-one",
        },
        expected_generation=4,
        idempotency_key="idem-ingress",
    )

    openai_request = parse_admin_request(json.loads(openai))
    ingress_request = parse_admin_request(json.loads(ingress))

    assert openai_request.operation == "openai.auth.apply"
    assert openai_request.arguments["plan_id"] == "plan-one"
    assert ingress_request.arguments["credential_kind"] == "openai.auth-json"
    assert ingress_request.arguments["plan_id"] == "plan-one"


def test_real_usage_parsers_accept_canonical_step_up_session_and_receipt() -> None:
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
    session = parse_secret_ingress_session(
        {
            "schema_version": 1,
            "id": "ingress:one",
            "account_ref": "openai-one",
            "plan_id": "plan-one",
            "expires_at": "2026-08-29T12:02:00Z",
            "expected_generation": 4,
        }
    )
    receipt = parse_secret_ingress_receipt(
        {
            "schema_version": 1,
            "session_id": "ingress:one",
            "account_ref": "openai-one",
            "state": "consumed",
            "generation": 4,
        }
    )
    assert session.plan_id == "plan-one"
    assert receipt.session_id == session.id


def test_real_usage_producer_server_consumer_secret_apply_flow(tmp_path) -> None:
    service, _owners = service_at()
    create_body, _ = _encode_request(
        "secret.ingress.create",
        {
            "account_ref": "google-one",
            "credential_type": "google_oauth_client_json",
            "plan_id": "plan-one",
        },
        expected_generation=4,
        idempotency_key="idem-create",
    )
    apply_body, _ = _encode_request(
        "google.oauth-client-import.apply",
        {"account_ref": "google-one", "plan_id": "plan-one"},
        expected_generation=4,
        idempotency_key="idem-apply",
    )
    with _running_server(tmp_path, service=service) as (server, _service):
        created = _request(
            server,
            "POST",
            "/admin/v1",
            create_body,
            _headers(**{"X-Masterjet-Step-Up": _totp()}),
        )
        session = _decode_response(
            "secret.ingress.create",
            {
                "account_ref": "google-one",
                "credential_type": "google_oauth_client_json",
                "plan_id": "plan-one",
            },
            (created[0], created[2]),
        )
        uploaded = _request(
            server,
            "PUT",
            "/admin/v1/secret-ingress-sessions/" + session.id,
            b"client-json",
            _headers(**{"Content-Type": "application/octet-stream"}),
        )
        receipt = _decode_response(
            "secret.ingress.put",
            {"session_id": session.id},
            (uploaded[0], uploaded[2]),
        )
        applied = _request(server, "POST", "/admin/v1", apply_body, _headers())
        operation = _decode_response(
            "google.oauth-client-import.apply",
            {"account_ref": "google-one", "plan_id": "plan-one"},
            (applied[0], applied[2]),
        )
    assert receipt.generation == 5
    assert operation.kind == "google.oauth-client-import.apply"
    assert operation.resulting_generation == receipt.generation
