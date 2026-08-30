from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime
import base64
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import socket
import threading

import pytest

from codex_master.admin_auth import MasterjetBearerVerifier, TotpStepUpVerifier
from codex_master.admin_contracts import AdminPrincipalV1, AdminRequestV1, HiveProblemV1
from codex_master.admin_http import (
    AdminHttpServer,
    AdminHttpShutdownError,
    MAX_ADMIN_JSON_BYTES,
)
from codex_master.admin_service import (
    AdminDenied,
    AdminServiceError,
    SecretIngressCapabilityV1,
    MasterjetControlService,
)
from codex_master.credential_vault import CredentialVault
from codex_master.admin_secret_ingress import AdminSecretIngressOwner
from codex_master.hive.state import HiveStateError
from test_admin_service import service_at
from test_openai_credential_service import (
    auth_json,
    make_service as make_openai_service,
)
from test_google_oauth_session import (
    _client_json as google_client_json,
    _import_client as import_google_client,
    _service as make_google_service,
)


NOW = 2_000_000_000
ORIGIN = "masterjet.example.test"
DIGEST = "sha256:" + "a" * 64
TOTP_SECRET = b"12345678901234567890"


def _problem(code: str) -> HiveProblemV1:
    return HiveProblemV1(
        code=code,
        severity="error",
        title="Request failed",
        detail="Request could not be completed",
        effect="No action was started",
        action="Review access and retry",
        retryable=False,
        retry_after_seconds=None,
        correlation_id="corr-test",
        occurred_at=datetime(2026, 8, 29, tzinfo=UTC),
    )


class _Service:
    def __init__(self) -> None:
        self.calls: list[tuple[AdminPrincipalV1, AdminRequestV1]] = []
        self.secrets: list[bytes] = []
        self.consumed: set[str] = set()
        self.raise_marker = False
        self.known_failure = False
        self.capabilities: list[object] = []
        self.upload_reservations: list[tuple[str, str, int, str]] = []
        self.upload_rollbacks: list[object] = []
        self.sessions: set[str] = set()

    def handle(
        self,
        principal: AdminPrincipalV1,
        request: AdminRequestV1,
        *,
        ingress_session=None,
        oauth_code=None,
    ):
        del oauth_code
        if (
            ingress_session is None
            and request.operation
            in {
                "openai.auth.apply",
                "google.oauth.complete",
                "google.oauth-client-import.apply",
            }
            and "ingress-one" in self.consumed
        ):
            ingress_session = SecretIngressCapabilityV1(
                "ingress-one",
                principal.subject,
                str(request.arguments["account_ref"]),
                request.operation,
                {
                    "openai.auth.apply": "openai.auth-json",
                    "google.oauth.complete": "google-oauth-code",
                    "google.oauth-client-import.apply": "google.oauth-client",
                }[request.operation],
                request.arguments.get("transaction_id"),
                request.plan_digest or DIGEST,
                int(request.expected_generation),
                "idem-session",
                "idem-upload",
                request.idempotency_key or str(request.arguments.get("transaction_id")),
                int(request.expected_generation),
                int(request.expected_generation) + 1,
                NOW + 120.0,
            )
            principal = replace(principal, step_up=True)
        self.calls.append((principal, request))
        if ingress_session is not None:
            self.capabilities.append(ingress_session)
        if self.raise_marker:
            raise RuntimeError("private-exception-marker")
        if self.known_failure:
            raise AdminServiceError(_problem("control.owner_unavailable"))
        if (
            request.operation
            in {
                "secret.ingress.create",
                "google.provision.apply",
                "google.oauth-client-import.apply",
                "openai.auth.apply",
            }
            and not principal.step_up
        ):
            raise AdminDenied(_problem("authority.step_up_required"))
        if request.operation == "secret.ingress.create":
            self.sessions.add("ingress-one")
            return {
                "id": "ingress-one",
                "account_ref": "google-one",
                "state": "pending",
                "plan_digest": request.plan_digest,
                "expires_at": NOW + 120.0,
                "expected_generation": request.expected_generation,
                "session_generation": request.expected_generation,
            }
        return {
            "operation": request.operation,
            "step_up": principal.step_up,
            "state": "succeeded",
        }

    def reserve_secret_upload(
        self,
        principal: AdminPrincipalV1,
        session_id: str,
        *,
        expected_generation: int,
        idempotency_key: str,
    ):
        if not principal.step_up:
            raise AdminDenied(_problem("authority.step_up_required"))
        if session_id in self.consumed:
            raise AdminServiceError(_problem("credential.upload_expired"))
        reservation = (
            principal.subject,
            session_id,
            expected_generation,
            idempotency_key,
        )
        self.upload_reservations.append(reservation)
        return reservation

    def continue_secret_upload(
        self,
        principal: AdminPrincipalV1,
        session_id: str,
        *,
        expected_generation: int,
        idempotency_key: str,
    ):
        if session_id not in self.sessions:
            raise AdminServiceError(_problem("credential.upload_expired"))
        return self.reserve_secret_upload(
            replace(principal, step_up=True),
            session_id,
            expected_generation=expected_generation,
            idempotency_key=idempotency_key,
        )

    def rollback_secret_upload(self, upload_claim) -> None:
        self.upload_rollbacks.append(upload_claim)

    def put_secret(
        self,
        principal: AdminPrincipalV1,
        session_id: str,
        secret,
        *,
        upload_claim,
    ):
        if not principal.step_up:
            raise AdminDenied(_problem("authority.step_up_required"))
        if upload_claim not in self.upload_reservations:
            raise AdminServiceError(_problem("credential.upload_expired"))
        if session_id in self.consumed:
            raise AdminServiceError(_problem("credential.upload_expired"))
        self.consumed.add(session_id)
        self.secrets.append(bytes(secret))
        return {
            "session_id": session_id,
            "account_ref": "google-one",
            "state": "consumed",
            "generation": upload_claim[2] + 1,
        }


class _AccessVerifier:
    def __init__(self) -> None:
        self.assertions: list[str] = []

    def verify(self, assertion: str) -> AdminPrincipalV1:
        self.assertions.append(assertion)
        if assertion != "signed-access-assertion":
            raise AssertionError("test verifier received unexpected assertion")
        return AdminPrincipalV1(
            "cloudflare-user",
            ("fleet.read", "fleet.google.provision"),
            "cloudflare-access",
            False,
        )


def _private_fd(tmp_path: Path, name: str, payload: bytes) -> int:
    path = tmp_path / name
    path.write_bytes(payload)
    path.chmod(0o600)
    return os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)


def _totp() -> str:
    counter = NOW // 30
    digest = hmac.new(TOTP_SECRET, counter.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 15
    value = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


@contextmanager
def _running_server(
    tmp_path: Path,
    *,
    service: _Service | None = None,
    trusted_proxy_addresses: tuple[str, ...] | None = None,
    authority_mode: str = "bearer",
    access_verifier=None,
):
    service = _Service() if service is None else service
    bearer_fd = _private_fd(tmp_path, "bearer", b"remote-bearer")
    totp_fd = _private_fd(tmp_path, "totp", base64.b32encode(TOTP_SECRET))
    try:
        bearer = MasterjetBearerVerifier.from_fd(
            bearer_fd,
            subject="usage-service",
            scopes=(
                "fleet.read",
                "fleet.google.provision",
                "fleet.google.oauth",
                "fleet.secrets.ingress",
            ),
        )
        totp = TotpStepUpVerifier.from_fd(
            totp_fd,
            clock=lambda: NOW,
            skew_steps=0,
            replay_state_path=tmp_path / "totp-replay-state",
        )
    finally:
        os.close(bearer_fd)
        os.close(totp_fd)
    server = AdminHttpServer(
        ("127.0.0.1", 0),
        service,
        authority_mode=authority_mode,
        bearer_verifier=bearer,
        access_verifier=access_verifier,
        step_up_verifier=totp,
        origin_host=ORIGIN,
        trusted_proxy_addresses=trusted_proxy_addresses,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, service
    finally:
        server.shutdown()
        server.drain(2)
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()


def _headers(**changes: str) -> dict[str, str]:
    result = {
        "Authorization": "Bearer remote-bearer",
        "Host": ORIGIN,
        "X-Forwarded-Host": ORIGIN,
        "X-Forwarded-Proto": "https",
        "Content-Type": "application/json",
        "X-Masterjet-Operation": "secret.ingress.put",
        "X-Masterjet-Expected-Generation": "4",
        "Idempotency-Key": "idem-upload",
    }
    result.update(changes)
    return result


def _request(server, method: str, target: str, body: bytes, headers: dict[str, str]):
    connection = http.client.HTTPConnection(*server.server_address, timeout=2)
    connection.request(method, target, body=body, headers=headers)
    response = connection.getresponse()
    payload = response.read()
    response_headers = dict(response.getheaders())
    connection.close()
    return response.status, response_headers, payload


def _document(operation: str, arguments: dict[str, object], **extra: object) -> bytes:
    value: dict[str, object] = {
        "schema_version": 1,
        "operation": operation,
        "arguments": arguments,
    }
    value.update(extra)
    return json.dumps(value, separators=(",", ":")).encode("ascii")


def _secret_session_document() -> bytes:
    return _document(
        "secret.ingress.create",
        {"account_ref": "google-one", "credential_kind": "google.oauth-client"},
        expected_generation=4,
        idempotency_key="idem-session",
        plan_digest=DIGEST,
    )


def _secret_payload() -> bytes:
    return b'{"tokens":{"access_' + b'token":"marker"}}'


def test_http_dispatches_only_parsed_admin_request_and_sets_no_store(tmp_path) -> None:
    with _running_server(tmp_path) as (server, service):
        status, headers, payload = _request(
            server,
            "POST",
            "/admin/v1",
            _document("google.accounts.list", {}),
            _headers(),
        )

    assert status == 200
    assert headers["Cache-Control"] == "no-store"
    assert headers["Content-Type"] == "application/json"
    assert json.loads(payload)["operation"] == "google.accounts.list"
    assert type(service.calls[0][1]) is AdminRequestV1


@pytest.mark.parametrize(
    ("target", "operation"),
    [
        ("/admin/v1/ollama/models", "ollama.models.list"),
        ("/admin/v1/ollama/instances", "ollama.instances.list"),
    ],
)
def test_ollama_rest_queries_bind_exact_operation(tmp_path, target, operation) -> None:
    with _running_server(tmp_path) as (server, service):
        status, headers, payload = _request(server, "GET", target, b"", _headers())

    assert status == 200
    assert headers["Cache-Control"] == "no-store"
    assert json.loads(payload)["operation"] == operation
    assert service.calls[0][1] == AdminRequestV1(operation, {}, None, None, None)


@pytest.mark.parametrize(
    ("target", "operation", "arguments"),
    [
        ("/admin/v1/hosts", "hosts.list", {}),
        ("/admin/v1/openai/accounts", "openai.accounts.list", {}),
        ("/admin/v1/google/accounts", "google.accounts.list", {}),
        (
            "/admin/v1/google/accounts/google-one",
            "google.projects.list",
            {"account_ref": "google-one"},
        ),
        (
            "/admin/v1/operations/op-one",
            "operations.get",
            {"operation_id": "op-one"},
        ),
    ],
)
def test_documented_rest_queries_bind_exact_operation(
    tmp_path, target, operation, arguments
) -> None:
    with _running_server(tmp_path) as (server, service):
        status, headers, payload = _request(server, "GET", target, b"", _headers())

    assert status == 200
    assert headers["Cache-Control"] == "no-store"
    assert json.loads(payload)["operation"] == operation
    assert service.calls[0][1] == AdminRequestV1(
        operation, arguments, None, None, None
    )


def test_documented_rest_response_keeps_exact_service_contract(tmp_path) -> None:
    class ContractService(_Service):
        def handle(self, principal, request, **_kwargs):
            self.calls.append((principal, request))
            return {"accounts": []}

    with _running_server(tmp_path, service=ContractService()) as (server, _service):
        status, _headers_out, payload = _request(
            server, "GET", "/admin/v1/google/accounts", b"", _headers()
        )

    assert status == 200
    assert json.loads(payload) == {"schema_version": 1, "accounts": []}


@pytest.mark.parametrize(
    ("target", "operation", "arguments", "extra"),
    [
        (
            "/admin/v1/openai/accounts",
            "openai.accounts.add",
            {"account_ref": "openai-two", "label": "OpenAI Two"},
            {"expected_generation": 4, "idempotency_key": "account-add"},
        ),
        (
            "/admin/v1/openai/accounts/openai-one/auth-sync-plans",
            "openai.auth.plan",
            {"account_ref": "openai-one"},
            {"expected_generation": 4, "idempotency_key": "auth-plan"},
        ),
        (
            f"/admin/v1/openai/accounts/openai-one/auth-sync-plans/{DIGEST}/apply",
            "openai.auth.apply",
            {"account_ref": "openai-one"},
            {
                "expected_generation": 4,
                "idempotency_key": "auth-apply",
                "plan_digest": DIGEST,
            },
        ),
        (
            "/admin/v1/secret-ingress-sessions",
            "secret.ingress.create",
            {"account_ref": "openai-one", "credential_kind": "openai.auth-json"},
            {
                "expected_generation": 4,
                "idempotency_key": "ingress-create",
                "plan_digest": DIGEST,
            },
        ),
        (
            "/admin/v1/google/oauth-transactions",
            "google.oauth.begin",
            {
                "account_ref": "google-one",
                "oauth_client_ref": "client-one",
                "redirect_uri": "http://127.0.0.1/callback",
                "scope_profile": "inventory",
            },
            {"expected_generation": 4, "idempotency_key": "oauth-begin"},
        ),
        (
            "/admin/v1/google/oauth-transactions/transaction-one/complete",
            "google.oauth.complete",
            {
                "account_ref": "google-one",
                "transaction_id": "transaction-one",
                "redirect_uri": "http://127.0.0.1/callback",
                "state": "state-one",
            },
            {"expected_generation": 4},
        ),
        (
            "/admin/v1/google/oauth-client-import-plans",
            "google.oauth-client-import.plan",
            {"account_ref": "google-one"},
            {"expected_generation": 4, "idempotency_key": "client-plan"},
        ),
        (
            f"/admin/v1/google/oauth-client-import-plans/{DIGEST}/apply",
            "google.oauth-client-import.apply",
            {"account_ref": "google-one"},
            {
                "expected_generation": 4,
                "idempotency_key": "client-apply",
                "plan_digest": DIGEST,
            },
        ),
        (
            "/admin/v1/google/inventory-refreshes",
            "google.inventory.refresh",
            {},
            {"expected_generation": 4, "idempotency_key": "inventory-refresh"},
        ),
        (
            "/admin/v1/google/provision-plans",
            "google.provision.plan",
            {"account_ref": "google-one"},
            {"expected_generation": 4, "idempotency_key": "provision-plan"},
        ),
        (
            f"/admin/v1/google/provision-plans/{DIGEST}/apply",
            "google.provision.apply",
            {"account_ref": "google-one"},
            {
                "expected_generation": 4,
                "idempotency_key": "provision-apply",
                "plan_digest": DIGEST,
            },
        ),
        (
            "/admin/v1/google/billing-bind-plans",
            "google.billing.plan",
            {
                "account_ref": "google-one",
                "project_ref": "project-one",
                "billing_ref": "billing-one",
            },
            {"expected_generation": 4, "idempotency_key": "billing-plan"},
        ),
        (
            "/admin/v1/google/billing-bind-plans/plan-one/apply",
            "google.billing.apply",
            {
                "account_ref": "google-one",
                "project_ref": "project-one",
                "billing_ref": "billing-one",
                "plan_id": "plan-one",
            },
            {
                "expected_generation": 4,
                "idempotency_key": "billing-apply",
                "plan_digest": DIGEST,
            },
        ),
    ],
)
def test_documented_rest_commands_bind_route_identity(
    tmp_path, target, operation, arguments, extra
) -> None:
    with _running_server(tmp_path) as (server, service):
        status, _headers_out, payload = _request(
            server,
            "POST",
            target,
            _document(operation, arguments, **extra),
            _headers(**{"X-Masterjet-Step-Up": _totp()}),
        )

    assert status == 200
    assert json.loads(payload)["schema_version"] == 1
    assert service.calls[0][1] == AdminRequestV1(
        operation,
        arguments,
        extra.get("expected_generation"),
        extra.get("idempotency_key"),
        extra.get("plan_digest"),
    )


def test_documented_rest_path_and_request_identity_cannot_diverge(tmp_path) -> None:
    with _running_server(tmp_path) as (server, service):
        status, _headers_out, payload = _request(
            server,
            "POST",
            "/admin/v1/google/oauth-transactions/transaction-one/complete",
            _document(
                "google.oauth.complete",
                {
                    "account_ref": "google-one",
                    "transaction_id": "transaction-two",
                    "redirect_uri": "http://127.0.0.1/callback",
                    "state": "state-one",
                },
                expected_generation=4,
            ),
            _headers(),
        )

    assert status == 400
    assert json.loads(payload)["code"] == "control.request_invalid"
    assert service.calls == []


@pytest.mark.parametrize(
    "method", ["DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"]
)
def test_ollama_rest_queries_reject_unsupported_methods(tmp_path, method) -> None:
    with _running_server(tmp_path) as (server, service):
        status, _headers_out, payload = _request(
            server,
            method,
            "/admin/v1/ollama/models",
            b"",
            _headers(),
        )

    assert status == 405
    if method != "HEAD":
        assert json.loads(payload)["code"] == "control.route_not_found"
    assert service.calls == []


@pytest.mark.parametrize(
    ("target", "operation", "arguments", "extra"),
    [
        (
            "/admin/v1/ollama/instance-plans",
            "ollama.instance.plan",
            {
                "ref": "quiet-runner",
                "label": "Quiet Runner",
                "host_ref": "control-host",
                "ollama_executable": "/usr/bin/ollama",
                "models_directory": "/srv/ollama/models",
                "selected_model_refs": ["model-a"],
                "allowed_cpus": "4-7",
                "cpu_quota_percent": 350,
                "cpu_weight": 40,
            },
            {"expected_generation": 3, "idempotency_key": "plan-one"},
        ),
        (
            "/admin/v1/ollama/instance-plans/plan-one/apply",
            "ollama.instance.apply",
            {"plan_id": "plan-one"},
            {
                "expected_generation": 3,
                "idempotency_key": "apply-one",
                "plan_digest": DIGEST,
            },
        ),
        (
            "/admin/v1/ollama/instances/quiet-runner/probe",
            "ollama.instance.probe",
            {"instance_ref": "quiet-runner"},
            {"expected_generation": 4, "idempotency_key": "probe-one"},
        ),
    ],
)
def test_ollama_rest_commands_bind_route_identity(
    tmp_path, target, operation, arguments, extra
) -> None:
    with _running_server(tmp_path) as (server, service):
        status, _headers_out, payload = _request(
            server,
            "POST",
            target,
            _document(operation, arguments, **extra),
            _headers(),
        )

    assert status == 200
    assert json.loads(payload)["operation"] == operation
    assert service.calls[0][1].operation == operation


def test_ollama_rest_path_and_request_identity_cannot_diverge(tmp_path) -> None:
    with _running_server(tmp_path) as (server, service):
        status, _headers_out, payload = _request(
            server,
            "POST",
            "/admin/v1/ollama/instance-plans/plan-one/apply",
            _document(
                "ollama.instance.apply",
                {"plan_id": "plan-two"},
                expected_generation=3,
                idempotency_key="apply-one",
                plan_digest=DIGEST,
            ),
            _headers(),
        )

    assert status == 400
    assert json.loads(payload)["code"] == "control.request_invalid"
    assert service.calls == []


def test_cloudflare_mode_uses_assertion_header_without_cookie_or_bearer(
    tmp_path,
) -> None:
    verifier = _AccessVerifier()
    headers = _headers(**{"Cf-Access-Jwt-Assertion": "signed-access-assertion"})
    del headers["Authorization"]
    with _running_server(
        tmp_path, authority_mode="cloudflare", access_verifier=verifier
    ) as (server, service):
        status, _headers_out, _payload = _request(
            server,
            "POST",
            "/admin/v1",
            _document("google.accounts.list", {}),
            headers,
        )

    assert status == 200
    assert verifier.assertions == ["signed-access-assertion"]
    assert service.calls[0][0].subject == "cloudflare-user"


def test_require_both_intersects_server_scopes_and_uses_cloudflare_subject(
    tmp_path,
) -> None:
    verifier = _AccessVerifier()
    headers = _headers(**{"Cf-Access-Jwt-Assertion": "signed-access-assertion"})
    with _running_server(
        tmp_path, authority_mode="require_both", access_verifier=verifier
    ) as (server, service):
        status, _headers_out, _payload = _request(
            server,
            "POST",
            "/admin/v1",
            _document("google.accounts.list", {}),
            headers,
        )

    assert status == 200
    principal = service.calls[0][0]
    assert principal.subject == "cloudflare-user"
    assert principal.scopes == ("fleet.read", "fleet.google.provision")
    assert principal.authentication == "cloudflare-access.masterjet-bearer"


def test_sensitive_request_returns_usage_compatible_authenticated_challenge(
    tmp_path,
) -> None:
    with _running_server(tmp_path) as (server, _service):
        status, _headers_out, payload = _request(
            server,
            "POST",
            "/admin/v1",
            _document(
                "google.provision.apply",
                {"account_ref": "google-one"},
                expected_generation=4,
                idempotency_key="idem-apply",
                plan_digest=DIGEST,
            ),
            _headers(),
        )

    assert status == 403
    assert json.loads(payload) == {
        "schema_version": 1,
        "code": "control.step_up_required",
        "severity": "warning",
        "title": "Step-up required",
        "detail": "Additional authentication is required.",
        "effect": "Operation is paused.",
        "action": "Complete step-up authentication.",
        "retryable": False,
        "retry_after_seconds": None,
        "correlation_id": json.loads(payload)["correlation_id"],
        "occurred_at": json.loads(payload)["occurred_at"],
    }


def test_fresh_totp_is_bound_to_only_current_request(tmp_path) -> None:
    body = _document(
        "google.provision.apply",
        {"account_ref": "google-one"},
        expected_generation=4,
        idempotency_key="idem-apply",
        plan_digest=DIGEST,
    )
    with _running_server(tmp_path) as (server, service):
        status, _headers_out, payload = _request(
            server,
            "POST",
            "/admin/v1",
            body,
            _headers(**{"X-Masterjet-Step-Up": _totp()}),
        )
        replay, _headers_out, replay_payload = _request(
            server,
            "POST",
            "/admin/v1",
            body,
            _headers(**{"X-Masterjet-Step-Up": _totp()}),
        )

    assert status == 200
    assert json.loads(payload)["state"] == "succeeded"
    assert service.calls[0][0].step_up is True
    assert replay == 403
    assert json.loads(replay_payload)["code"] == "authority.step_up_replayed"


def test_secret_ingress_flow_grant_covers_only_put_and_matching_apply(tmp_path) -> None:
    with _running_server(tmp_path) as (server, service):
        created, _headers_out, create_payload = _request(
            server,
            "POST",
            "/admin/v1",
            _secret_session_document(),
            _headers(**{"X-Masterjet-Step-Up": _totp()}),
        )
        put_headers = _headers(**{"Content-Type": "application/octet-stream"})
        uploaded, _headers_out, upload_payload = _request(
            server,
            "PUT",
            "/admin/v1/secret-ingress-sessions/ingress-one",
            _secret_payload(),
            put_headers,
        )
        apply_body = _document(
            "google.oauth-client-import.apply",
            {"account_ref": "google-one"},
            expected_generation=4,
            idempotency_key="idem-final",
            plan_digest=DIGEST,
        )
        applied, _headers_out, apply_payload = _request(
            server, "POST", "/admin/v1", apply_body, _headers()
        )

    assert created == uploaded == applied == 200
    assert json.loads(create_payload)["id"] == "ingress-one"
    assert json.loads(upload_payload)["state"] == "consumed"
    assert json.loads(apply_payload)["state"] == "succeeded"
    assert service.secrets == [_secret_payload()]


def test_known_apply_failure_rolls_back_flow_for_same_idempotent_retry(
    tmp_path,
) -> None:
    service = _Service()
    with _running_server(tmp_path, service=service) as (server, _service):
        _request(
            server,
            "POST",
            "/admin/v1",
            _secret_session_document(),
            _headers(**{"X-Masterjet-Step-Up": _totp()}),
        )
        _request(
            server,
            "PUT",
            "/admin/v1/secret-ingress-sessions/ingress-one",
            _secret_payload(),
            _headers(**{"Content-Type": "application/octet-stream"}),
        )
        body = _document(
            "google.oauth-client-import.apply",
            {"account_ref": "google-one"},
            expected_generation=4,
            idempotency_key="idem-final",
            plan_digest=DIGEST,
        )
        service.known_failure = True
        failed, _out, _payload = _request(server, "POST", "/admin/v1", body, _headers())
        service.known_failure = False
        retried, _out, _payload = _request(
            server, "POST", "/admin/v1", body, _headers()
        )

    assert failed == 503
    assert retried == 200
    assert len(service.capabilities) == 2


def test_real_service_create_put_apply_receives_exact_one_shot_capability(
    tmp_path,
) -> None:
    service, owners = service_at()
    with _running_server(tmp_path, service=service) as (server, _service):
        created, _out, _payload = _request(
            server,
            "POST",
            "/admin/v1",
            _secret_session_document(),
            _headers(**{"X-Masterjet-Step-Up": _totp()}),
        )
        uploaded, _out, _payload = _request(
            server,
            "PUT",
            "/admin/v1/secret-ingress-sessions/ingress-one",
            _secret_payload(),
            _headers(**{"Content-Type": "application/octet-stream"}),
        )
        applied, _out, _payload = _request(
            server,
            "POST",
            "/admin/v1",
            _document(
                "google.oauth-client-import.apply",
                {"account_ref": "google-one"},
                expected_generation=4,
                idempotency_key="idem-final",
                plan_digest=DIGEST,
            ),
            _headers(),
        )
        replay, _out, _payload = _request(
            server,
            "POST",
            "/admin/v1",
            _document(
                "google.oauth-client-import.apply",
                {"account_ref": "google-one"},
                expected_generation=4,
                idempotency_key="idem-final",
                plan_digest=DIGEST,
            ),
            _headers(),
        )
    assert (created, uploaded, applied) == (200, 200, 200)
    assert replay == 200
    assert owners.secret_ingress.resolve_calls == 2
    capability = owners.secret_ingress.last_capability
    assert type(capability) is SecretIngressCapabilityV1
    assert capability.subject == "usage-service"
    assert capability.account_ref == "google-one"
    assert capability.operation == "google.oauth-client-import.apply"
    assert capability.credential_kind == "google.oauth-client"
    assert capability.plan_digest == DIGEST
    assert capability.expected_generation == 4
    assert capability.create_idempotency_key == "idem-session"
    assert capability.upload_idempotency_key == "idem-upload"
    assert capability.apply_idempotency_key == "idem-final"
    assert capability.receipt_generation == 5


def test_http_restart_continues_uploaded_session_from_concrete_owner(
    tmp_path,
) -> None:
    """Break caught: fresh HTTP process must not depend on `_FlowGrants`."""

    _unused, owners = service_at()
    openai = make_openai_service(
        tmp_path / "openai", registered_backend="acct-one", identity_generation=2
    )
    plan = openai.plan_auth_sync(
        "openai-one", expected_generation=2, idempotency_key="openai-plan"
    )
    service = MasterjetControlService.with_admin_secret_ingress(
        secret_ingress_state_root=tmp_path / "ingress-state",
        secret_ingress_vault=CredentialVault.for_test(
            tmp_path / "ingress-vault", key=b"i" * 32, clock=lambda: 1_000.0
        ),
        operation_store=owners.operation_store,
        openai_accounts=owners.openai_accounts,
        openai_credentials=openai,
        google_manager=owners.google_manager,
        google_oauth_factory=lambda _ingress: owners.google_oauth,
        quota_collector=owners.quota_collector,
        google_provisioner=owners.google_provisioner,
        google_billing=owners.google_billing,
        host_registry=owners.hosts,
        clock=lambda: 1_000.0,
    )
    create_body = _document(
        "secret.ingress.create",
        {"account_ref": "openai-one", "credential_kind": "openai.auth-json"},
        expected_generation=2,
        idempotency_key="ingress-create",
        plan_digest="sha256:" + plan.plan_digest,
    )
    with _running_server(tmp_path, service=service) as (server, _service):
        created, _out, create_payload = _request(
            server,
            "POST",
            "/admin/v1",
            create_body,
            _headers(**{"X-Masterjet-Step-Up": _totp()}),
        )
        session_id = json.loads(create_payload)["id"]
        uploaded, _out, _payload = _request(
            server,
            "PUT",
            f"/admin/v1/secret-ingress-sessions/{session_id}",
            auth_json("acct-one"),
            _headers(
                **{
                    "Content-Type": "application/octet-stream",
                    "X-Masterjet-Expected-Generation": "2",
                    "Idempotency-Key": "ingress-upload",
                }
            ),
        )

    with _running_server(tmp_path, service=service) as (server, _service):
        applied, _out, apply_payload = _request(
            server,
            "POST",
            "/admin/v1",
            _document(
                "openai.auth.apply",
                {"account_ref": "openai-one"},
                expected_generation=2,
                idempotency_key="openai-plan",
                plan_digest="sha256:" + plan.plan_digest,
            ),
            _headers(),
        )

    assert (created, uploaded, applied) == (200, 200, 200)
    assert json.loads(apply_payload)["state"] == "succeeded"


def test_http_restart_reconciles_revoked_apply_without_reapplying_business(
    tmp_path, monkeypatch
) -> None:
    """Break caught: revoke+journal failure must use public reconcile, not retry."""

    _unused, owners = service_at()
    openai = make_openai_service(
        tmp_path / "openai", registered_backend="acct-one", identity_generation=2
    )
    plan = openai.plan_auth_sync(
        "openai-one", expected_generation=2, idempotency_key="openai-plan"
    )

    def compose(openai_owner):
        return MasterjetControlService.with_admin_secret_ingress(
            secret_ingress_state_root=tmp_path / "ingress-state",
            secret_ingress_vault=CredentialVault.for_test(
                tmp_path / "ingress-vault", key=b"i" * 32, clock=lambda: 1_000.0
            ),
            operation_store=owners.operation_store,
            openai_accounts=owners.openai_accounts,
            openai_credentials=openai_owner,
            google_manager=owners.google_manager,
            google_oauth_factory=lambda _ingress: owners.google_oauth,
            quota_collector=owners.quota_collector,
            google_provisioner=owners.google_provisioner,
            google_billing=owners.google_billing,
            host_registry=owners.hosts,
            clock=lambda: 1_000.0,
        )

    service = compose(openai)
    create_body = _document(
        "secret.ingress.create",
        {"account_ref": "openai-one", "credential_kind": "openai.auth-json"},
        expected_generation=2,
        idempotency_key="ingress-create",
        plan_digest="sha256:" + plan.plan_digest,
    )
    apply_body = _document(
        "openai.auth.apply",
        {"account_ref": "openai-one"},
        expected_generation=2,
        idempotency_key="openai-plan",
        plan_digest="sha256:" + plan.plan_digest,
    )
    with _running_server(tmp_path, service=service) as (server, _service):
        _created, _out, create_payload = _request(
            server,
            "POST",
            "/admin/v1",
            create_body,
            _headers(**{"X-Masterjet-Step-Up": _totp()}),
        )
        session_id = json.loads(create_payload)["id"]
        uploaded, _out, _payload = _request(
            server,
            "PUT",
            f"/admin/v1/secret-ingress-sessions/{session_id}",
            auth_json("acct-one"),
            _headers(
                **{
                    "Content-Type": "application/octet-stream",
                    "X-Masterjet-Expected-Generation": "2",
                    "Idempotency-Key": "ingress-upload",
                }
            ),
        )

        real_write = AdminSecretIngressOwner._write_locked

        def fail_resolved(owner, document):
            if document["sessions"][session_id]["state"] == "resolved":
                raise RuntimeError("post-revoke journal failure")
            return real_write(owner, document)

        monkeypatch.setattr(AdminSecretIngressOwner, "_write_locked", fail_resolved)
        ambiguous, _out, _payload = _request(
            server, "POST", "/admin/v1", apply_body, _headers()
        )

    monkeypatch.setattr(AdminSecretIngressOwner, "_write_locked", real_write)
    restarted_openai = make_openai_service(
        tmp_path / "openai", registered_backend="acct-one", identity_generation=2
    )
    with _running_server(tmp_path, service=compose(restarted_openai)) as (
        server,
        _service,
    ):
        reconciled, _out, payload = _request(
            server, "POST", "/admin/v1", apply_body, _headers()
        )

    assert uploaded == 200
    assert ambiguous == 503
    assert reconciled == 200
    assert json.loads(payload)["state"] == "succeeded"


@pytest.mark.parametrize("unknown_journal_fault", [False, True])
def test_http_restart_recovers_openai_receipt_before_ingress_revoke(
    tmp_path, monkeypatch, unknown_journal_fault
) -> None:
    """Break caught: post-business fault must reconcile active unknown state."""

    _unused, owners = service_at()
    openai = make_openai_service(
        tmp_path / "openai", registered_backend="acct-one", identity_generation=2
    )
    plan = openai.plan_auth_sync(
        "openai-one", expected_generation=2, idempotency_key="openai-plan"
    )
    ingress_vault_root = tmp_path / "ingress-vault"

    class OpenAIOwner:
        def __init__(self, owner, *, fail_after_apply: bool) -> None:
            self.owner = owner
            self.fail_after_apply = fail_after_apply
            self.apply_calls = 0

        def __getattr__(self, name):
            return getattr(self.owner, name)

        def apply_auth_sync(self, plan, upload):
            self.apply_calls += 1
            if not self.fail_after_apply:
                raise AssertionError("business effect was reapplied")
            self.owner.apply_auth_sync(plan, upload)
            raise RuntimeError("fault after durable business receipt")

    def compose(openai_owner):
        return MasterjetControlService.with_admin_secret_ingress(
            secret_ingress_state_root=tmp_path / "ingress-state",
            secret_ingress_vault=CredentialVault.for_test(
                ingress_vault_root, key=b"i" * 32, clock=lambda: 1_000.0
            ),
            operation_store=owners.operation_store,
            openai_accounts=owners.openai_accounts,
            openai_credentials=openai_owner,
            google_manager=owners.google_manager,
            google_oauth_factory=lambda _ingress: owners.google_oauth,
            quota_collector=owners.quota_collector,
            google_provisioner=owners.google_provisioner,
            google_billing=owners.google_billing,
            host_registry=owners.hosts,
            clock=lambda: 1_000.0,
        )

    create_body = _document(
        "secret.ingress.create",
        {"account_ref": "openai-one", "credential_kind": "openai.auth-json"},
        expected_generation=2,
        idempotency_key="ingress-create",
        plan_digest="sha256:" + plan.plan_digest,
    )
    apply_body = _document(
        "openai.auth.apply",
        {"account_ref": "openai-one"},
        expected_generation=2,
        idempotency_key="openai-plan",
        plan_digest="sha256:" + plan.plan_digest,
    )
    first_owner = OpenAIOwner(openai, fail_after_apply=True)
    with _running_server(tmp_path, service=compose(first_owner)) as (server, _service):
        _created, _out, create_payload = _request(
            server,
            "POST",
            "/admin/v1",
            create_body,
            _headers(**{"X-Masterjet-Step-Up": _totp()}),
        )
        session_id = json.loads(create_payload)["id"]
        uploaded, _out, _payload = _request(
            server,
            "PUT",
            f"/admin/v1/secret-ingress-sessions/{session_id}",
            auth_json("acct-one"),
            _headers(
                **{
                    "Content-Type": "application/octet-stream",
                    "X-Masterjet-Expected-Generation": "2",
                    "Idempotency-Key": "ingress-upload",
                }
            ),
        )
        real_write = AdminSecretIngressOwner._write_locked
        journal_faults: list[str] = []

        def fail_unknown_journal(owner, document):
            if (
                unknown_journal_fault
                and document["sessions"][session_id]["state"] == "apply_unknown"
            ):
                journal_faults.append(session_id)
                raise RuntimeError("fault while journaling unknown outcome")
            return real_write(owner, document)

        monkeypatch.setattr(
            AdminSecretIngressOwner, "_write_locked", fail_unknown_journal
        )
        ambiguous, _out, ambiguous_payload = _request(
            server, "POST", "/admin/v1", apply_body, _headers()
        )

    monkeypatch.setattr(AdminSecretIngressOwner, "_write_locked", real_write)
    restarted_openai = make_openai_service(
        tmp_path / "openai", registered_backend="acct-one", identity_generation=2
    )
    restart_owner = OpenAIOwner(restarted_openai, fail_after_apply=False)
    with _running_server(tmp_path, service=compose(restart_owner)) as (
        server,
        _service,
    ):
        reconciled, _out, payload = _request(
            server, "POST", "/admin/v1", apply_body, _headers()
        )

    ingress_vault = CredentialVault.for_test(
        ingress_vault_root, key=b"i" * 32, clock=lambda: 1_000.0
    )
    assert (uploaded, ambiguous, reconciled) == (200, 503, 200)
    ambiguous_problem = json.loads(ambiguous_payload)
    assert ambiguous_problem["code"] == "control.owner_unavailable"
    assert ambiguous_problem["effect"] == "Action outcome is unknown"
    assert (
        ambiguous_problem["action"]
        == "Retry the identical request to reconcile outcome"
    )
    assert ambiguous_problem["retryable"] is True
    assert journal_faults == ([session_id] if unknown_journal_fault else [])
    assert first_owner.apply_calls == 1
    assert restart_owner.apply_calls == 0
    assert ingress_vault.projection_metadata(session_id) == ("revoked", 3)
    assert json.loads(payload)["state"] == "succeeded"


def test_google_oauth_code_crosses_only_typed_raw_ingress_boundary(tmp_path) -> None:
    service, owners = service_at()
    session = _document(
        "secret.ingress.create",
        {
            "account_ref": "google-one",
            "credential_kind": "google-oauth-code",
            "transaction_id": "transaction-one",
        },
        expected_generation=4,
        idempotency_key="idem-oauth-code",
        plan_digest=DIGEST,
    )
    with _running_server(tmp_path, service=service) as (server, _service):
        created, _out, _payload = _request(
            server,
            "POST",
            "/admin/v1",
            session,
            _headers(**{"X-Masterjet-Step-Up": _totp()}),
        )
        uploaded, _out, _payload = _request(
            server,
            "PUT",
            "/admin/v1/secret-ingress-sessions/ingress-one",
            b"oauth-code",
            _headers(**{"Content-Type": "application/octet-stream"}),
        )
        completed, _out, payload = _request(
            server,
            "POST",
            "/admin/v1",
            _document(
                "google.oauth.complete",
                {
                    "account_ref": "google-one",
                    "transaction_id": "transaction-one",
                    "redirect_uri": "http://127.0.0.1/callback",
                    "state": "state-one",
                },
                expected_generation=4,
            ),
            _headers(),
        )
    assert (created, uploaded, completed) == (200, 200, 200)
    assert b"oauth-code" not in payload
    assert owners.google_oauth.calls == ["complete"]
    capability = owners.secret_ingress.last_capability
    assert type(capability) is SecretIngressCapabilityV1
    assert capability.credential_kind == "google-oauth-code"
    assert capability.operation == "google.oauth.complete"


@pytest.mark.parametrize("unknown_journal_fault", [False, True])
def test_google_client_http_restart_reconciles_durable_owner_receipt(
    tmp_path, monkeypatch, unknown_journal_fault
) -> None:
    """Break caught: concrete Google receipt recovery must use public HTTP."""

    _unused, owners = service_at()
    (tmp_path / "google").mkdir()
    composed: dict[str, object] = {}

    def compose():
        def google_factory(ingress):
            google, _unused_ingress, _exchange, manager = make_google_service(
                tmp_path / "google", ingress=ingress
            )
            composed["ingress"] = ingress
            composed["google"] = google
            composed["manager"] = manager
            return google

        return MasterjetControlService.with_admin_secret_ingress(
            secret_ingress_state_root=tmp_path / "google-ingress-state",
            secret_ingress_vault=CredentialVault.for_test(
                tmp_path / "google-ingress-vault",
                key=b"g" * 32,
                clock=lambda: 1_000.0,
            ),
            operation_store=owners.operation_store,
            openai_accounts=owners.openai_accounts,
            openai_credentials=owners.openai_credentials,
            google_manager=owners.google_manager,
            google_oauth_factory=google_factory,
            quota_collector=owners.quota_collector,
            google_provisioner=owners.google_provisioner,
            google_billing=owners.google_billing,
            host_registry=owners.hosts,
            clock=lambda: 1_000.0,
        )

    service = compose()
    google = composed["google"]
    plan = google.plan_oauth_client_import(
        "google-account-01", expected_generation=1, idempotency_key="google-plan"
    )
    create_body = _document(
        "secret.ingress.create",
        {
            "account_ref": "google-account-01",
            "credential_kind": "google.oauth-client",
        },
        expected_generation=1,
        idempotency_key="google-ingress",
        plan_digest=plan.plan_digest,
    )
    apply_body = _document(
        "google.oauth-client-import.apply",
        {"account_ref": "google-account-01"},
        expected_generation=1,
        idempotency_key="google-plan",
        plan_digest=plan.plan_digest,
    )
    ingress = composed["ingress"]
    real_ack = ingress.acknowledge_oauth_client

    def fail_ack(*_args, **_kwargs):
        raise RuntimeError("fault before ingress acknowledgement")

    monkeypatch.setattr(ingress, "acknowledge_oauth_client", fail_ack)
    with _running_server(tmp_path, service=service) as (server, _service):
        _created, _out, create_payload = _request(
            server,
            "POST",
            "/admin/v1",
            create_body,
            _headers(**{"X-Masterjet-Step-Up": _totp()}),
        )
        session_id = json.loads(create_payload)["id"]
        uploaded, _out, _payload = _request(
            server,
            "PUT",
            f"/admin/v1/secret-ingress-sessions/{session_id}",
            google_client_json(),
            _headers(
                **{
                    "Content-Type": "application/octet-stream",
                    "X-Masterjet-Expected-Generation": "1",
                    "Idempotency-Key": "google-upload",
                }
            ),
        )
        real_write = AdminSecretIngressOwner._write_locked
        journal_faults: list[str] = []

        def fail_unknown_journal(owner, document):
            if (
                unknown_journal_fault
                and document["sessions"][session_id]["state"] == "apply_unknown"
            ):
                journal_faults.append(session_id)
                raise RuntimeError("fault while journaling unknown outcome")
            return real_write(owner, document)

        monkeypatch.setattr(
            AdminSecretIngressOwner, "_write_locked", fail_unknown_journal
        )
        ambiguous, _out, ambiguous_payload = _request(
            server, "POST", "/admin/v1", apply_body, _headers()
        )

    monkeypatch.setattr(AdminSecretIngressOwner, "_write_locked", real_write)
    monkeypatch.setattr(ingress, "acknowledge_oauth_client", real_ack)
    with _running_server(tmp_path, service=compose()) as (server, _service):
        reconciled, _out, payload = _request(
            server, "POST", "/admin/v1", apply_body, _headers()
        )

    assert (uploaded, ambiguous, reconciled) == (200, 503, 200)
    ambiguous_problem = json.loads(ambiguous_payload)
    assert ambiguous_problem["code"] == "control.owner_unavailable"
    assert ambiguous_problem["effect"] == "Action outcome is unknown"
    assert (
        ambiguous_problem["action"]
        == "Retry the identical request to reconcile outcome"
    )
    assert ambiguous_problem["retryable"] is True
    assert journal_faults == ([session_id] if unknown_journal_fault else [])
    assert json.loads(payload)["account_ref"] == "google-account-01"
    google_state = json.loads(
        (tmp_path / "google" / "oauth-state" / "google-oauth-control.json").read_text()
    )
    assert [record["state"] for record in google_state["imports"]] == ["succeeded"]


def _real_google_list_service(tmp_path):
    google_root = tmp_path / "google-list"
    google_root.mkdir()
    google, ingress, _exchange, manager = make_google_service(google_root)
    _plan, _session, imported = import_google_client(google, ingress)
    _unused, owners = service_at()
    service = MasterjetControlService(
        operation_store=owners.operation_store,
        openai_accounts=owners.openai_accounts,
        openai_credentials=owners.openai_credentials,
        google_manager=manager,
        google_oauth=google,
        quota_collector=owners.quota_collector,
        google_provisioner=owners.google_provisioner,
        google_billing=owners.google_billing,
        host_registry=owners.hosts,
        secret_ingress=owners.secret_ingress,
    )
    return service, google, imported


def test_google_accounts_http_projects_real_bound_opaque_oauth_client_ref(
    tmp_path,
) -> None:
    service, _google, imported = _real_google_list_service(tmp_path)

    with _running_server(tmp_path, service=service) as (server, _service):
        status, _headers_out, payload = _request(
            server,
            "POST",
            "/admin/v1",
            _document("google.accounts.list", {}),
            _headers(),
        )

    document = json.loads(payload)
    account = next(
        item for item in document["accounts"] if item["ref"] == "google-account-01"
    )
    assert status == 200
    assert document["schema_version"] == 1
    assert account["default_oauth_client_ref"] == imported.client_ref
    assert account["oauth_client_availability"] == "available"
    assert set(account) == {
        "ref",
        "label",
        "enabled",
        "subject_bound",
        "oauth_state",
        "inventory_generation",
        "quota_state",
        "project_count",
        "billing_count",
        "reload_state",
        "default_oauth_client_ref",
        "oauth_client_availability",
    }
    lowered = payload.lower()
    assert b"private-client-secret" not in lowered
    assert b"client_secret" not in lowered
    assert b"577074103233-clientpart" not in lowered


@pytest.mark.parametrize("fault_phase", ["enter", "exit"])
def test_google_accounts_http_degrades_oauth_journal_lock_fault(
    tmp_path, monkeypatch, fault_phase
) -> None:
    service, google, _imported = _real_google_list_service(tmp_path)

    @contextmanager
    def unavailable_lock():
        if fault_phase == "enter":
            raise HiveStateError("state_lock_unavailable")
        yield
        raise HiveStateError("state_lock_unavailable")

    monkeypatch.setattr(google._state, "locked", unavailable_lock)
    with _running_server(tmp_path, service=service) as (server, _service):
        status, _headers_out, payload = _request(
            server,
            "POST",
            "/admin/v1",
            _document("google.accounts.list", {}),
            _headers(),
        )

    document = json.loads(payload)
    account = next(
        item for item in document["accounts"] if item["ref"] == "google-account-01"
    )
    assert status == 200
    assert document["schema_version"] == 1
    assert account["default_oauth_client_ref"] is None
    assert account["oauth_client_availability"] == "unavailable"


def test_secret_ingress_is_one_shot_with_gone_response(tmp_path) -> None:
    with _running_server(tmp_path) as (server, service):
        _request(
            server,
            "POST",
            "/admin/v1",
            _secret_session_document(),
            _headers(**{"X-Masterjet-Step-Up": _totp()}),
        )
        raw_headers = _headers(**{"Content-Type": "application/octet-stream"})
        first, _headers_out, _payload = _request(
            server,
            "PUT",
            "/admin/v1/secret-ingress-sessions/ingress-one",
            b"first",
            raw_headers,
        )
        second, _headers_out, payload = _request(
            server,
            "PUT",
            "/admin/v1/secret-ingress-sessions/ingress-one",
            b"again",
            raw_headers,
        )

    assert first == 200
    assert second == 410
    assert json.loads(payload)["code"] == "credential.upload_expired"
    assert service.secrets == [b"first"]


@pytest.mark.parametrize(
    "headers",
    [
        _headers(**{"X-Forwarded-Proto": "http"}),
        _headers(**{"X-Forwarded-Host": "attacker.example"}),
        _headers(**{"Host": "attacker.example"}),
    ],
)
def test_origin_and_forwarded_headers_fail_closed(tmp_path, headers) -> None:
    with _running_server(tmp_path) as (server, _service):
        status, _headers_out, payload = _request(
            server,
            "POST",
            "/admin/v1",
            _document("google.accounts.list", {}),
            headers,
        )

    assert status == 400
    assert json.loads(payload)["code"] == "control.origin_invalid"


def test_duplicate_forwarded_header_is_rejected(tmp_path) -> None:
    with _running_server(tmp_path) as (server, _service):
        connection = http.client.HTTPConnection(*server.server_address, timeout=2)
        body = _document("google.accounts.list", {})
        connection.putrequest("POST", "/admin/v1", skip_host=True)
        for name, value in _headers().items():
            connection.putheader(name, value)
        connection.putheader("X-Forwarded-Proto", "https")
        connection.putheader("Content-Length", str(len(body)))
        connection.endheaders(body)
        response = connection.getresponse()
        payload = response.read()
        connection.close()

    assert response.status == 400
    assert json.loads(payload)["code"] == "control.origin_invalid"


def test_forwarded_headers_are_ignored_from_untrusted_private_peer(tmp_path) -> None:
    with _running_server(tmp_path, trusted_proxy_addresses=("10.0.0.8",)) as (
        server,
        _service,
    ):
        status, _headers_out, payload = _request(
            server,
            "POST",
            "/admin/v1",
            _document("google.accounts.list", {}),
            _headers(),
        )

    assert status == 400
    assert json.loads(payload)["code"] == "control.origin_invalid"


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("/unknown", 404),
        ("/admin%2Fv1", 404),
        ("/admin/v1?operation=google.accounts.list", 404),
        ("/admin/v1/secret-ingress-sessions/ingress%2Done", 404),
    ],
)
def test_unknown_or_encoded_routes_are_rejected(tmp_path, target, expected) -> None:
    with _running_server(tmp_path) as (server, _service):
        status, _headers_out, _payload = _request(
            server, "POST", target, b"{}", _headers()
        )

    assert status == expected


def test_usage_percent_encoded_session_id_is_decoded_once(tmp_path) -> None:
    with _running_server(tmp_path) as (server, service):
        _request(
            server,
            "POST",
            "/admin/v1",
            _secret_session_document(),
            _headers(**{"X-Masterjet-Step-Up": _totp()}),
        )
        service.calls.clear()
        status, _out, _payload = _request(
            server,
            "PUT",
            "/admin/v1/secret-ingress-sessions/ingress%3Aone",
            b"secret",
            _headers(**{"Content-Type": "application/octet-stream"}),
        )
    assert status != 404


@pytest.mark.parametrize("suffix", ["bad%2Fpath", "bad%00", "bad%252Fpath"])
def test_ingress_route_rejects_encoded_delimiters_and_double_encoding(
    tmp_path, suffix
) -> None:
    with _running_server(tmp_path) as (server, _service):
        status, _out, _payload = _request(
            server,
            "PUT",
            "/admin/v1/secret-ingress-sessions/" + suffix,
            b"secret",
            _headers(**{"Content-Type": "application/octet-stream"}),
        )
    assert status == 404


@pytest.mark.parametrize("method", ["HEAD", "OPTIONS", "TRACE"])
def test_all_unsupported_methods_use_json_no_store_close(tmp_path, method) -> None:
    with _running_server(tmp_path) as (server, _service):
        status, headers, payload = _request(
            server, method, "/admin/v1", b"", _headers()
        )
    assert status == 405
    assert headers["Content-Type"] == "application/json"
    assert headers["Cache-Control"] == "no-store"
    assert headers["Connection"] == "close"
    if method != "HEAD":
        assert json.loads(payload)["code"] == "control.route_not_found"


def test_arbitrary_extension_method_uses_json_no_store_close(tmp_path) -> None:
    with _running_server(tmp_path) as (server, _service):
        status, headers, payload = _request(
            server, "PROPFIND", "/admin/v1", b"", _headers()
        )
    assert status == 405
    assert headers["Content-Type"] == "application/json"
    assert headers["Cache-Control"] == "no-store"
    assert headers["Connection"] == "close"
    assert json.loads(payload)["code"] == "control.route_not_found"


def test_fresh_totp_cannot_upload_without_matching_flow_grant(tmp_path) -> None:
    service = _Service()
    with _running_server(tmp_path, service=service) as (server, _service):
        status, _headers_out, payload = _request(
            server,
            "PUT",
            "/admin/v1/secret-ingress-sessions/orphan-session",
            b"secret-after-restart",
            _headers(
                **{
                    "Content-Type": "application/octet-stream",
                    "X-Masterjet-Step-Up": _totp(),
                }
            ),
        )
    assert status in {403, 410}
    assert json.loads(payload)["code"] in {
        "authority.step_up_required",
        "credential.upload_expired",
    }
    assert service.secrets == []
    assert service.upload_reservations == []


def test_matching_flow_reserves_owner_before_raw_put(tmp_path) -> None:
    service = _Service()
    with _running_server(tmp_path, service=service) as (server, _service):
        _request(
            server,
            "POST",
            "/admin/v1",
            _secret_session_document(),
            _headers(**{"X-Masterjet-Step-Up": _totp()}),
        )
        status, _headers_out, payload = _request(
            server,
            "PUT",
            "/admin/v1/secret-ingress-sessions/ingress-one",
            b"secret",
            _headers(**{"Content-Type": "application/octet-stream"}),
        )

    assert status == 200
    assert service.upload_reservations == [
        ("usage-service", "ingress-one", 4, "idem-upload")
    ]
    assert service.secrets == [b"secret"]
    assert json.loads(payload)["generation"] == 5


def test_oversized_content_length_is_rejected_without_owner_call(tmp_path) -> None:
    with _running_server(tmp_path) as (server, service):
        connection = http.client.HTTPConnection(*server.server_address, timeout=2)
        connection.putrequest("POST", "/admin/v1", skip_host=True)
        for name, value in _headers().items():
            connection.putheader(name, value)
        connection.putheader("Content-Length", str(MAX_ADMIN_JSON_BYTES + 1))
        connection.endheaders()
        response = connection.getresponse()
        payload = response.read()
        connection.close()

    assert response.status == 413
    assert json.loads(payload)["code"] == "control.request_too_large"
    assert service.calls == []


def test_expect_continue_is_rejected_before_request_body(tmp_path) -> None:
    body = _document("google.accounts.list", {})
    with _running_server(tmp_path) as (server, service):
        connection = http.client.HTTPConnection(*server.server_address, timeout=2)
        connection.putrequest("POST", "/admin/v1", skip_host=True)
        for name, value in _headers().items():
            connection.putheader(name, value)
        connection.putheader("Expect", "100-continue")
        connection.putheader("Content-Length", str(len(body)))
        connection.endheaders()
        response = connection.getresponse()
        payload = response.read()
        connection.close()

    assert response.status == 417
    assert json.loads(payload)["code"] == "control.request_invalid"
    assert service.calls == []


def test_chunked_request_is_rejected(tmp_path) -> None:
    with _running_server(tmp_path) as (server, _service):
        client = socket.create_connection(server.server_address, timeout=2)
        request = (
            "POST /admin/v1 HTTP/1.1\r\n"
            f"Host: {ORIGIN}\r\n"
            f"X-Forwarded-Host: {ORIGIN}\r\n"
            "X-Forwarded-Proto: https\r\n"
            "Authorization: Bearer remote-bearer\r\n"
            "Content-Type: application/json\r\n"
            "Transfer-Encoding: chunked\r\n\r\n"
            "2\r\n{}\r\n0\r\n\r\n"
        ).encode("ascii")
        client.sendall(request)
        response = b""
        while True:
            chunk = client.recv(4096)
            if not chunk:
                break
            response += chunk
        client.close()

    assert b" 400 " in response.split(b"\r\n", 1)[0]
    assert b"control.request_invalid" in response


def test_incomplete_body_after_connection_close_is_rejected(tmp_path) -> None:
    with _running_server(tmp_path) as (server, _service):
        client = socket.create_connection(server.server_address, timeout=2)
        request = (
            "POST /admin/v1 HTTP/1.1\r\n"
            f"Host: {ORIGIN}\r\n"
            f"X-Forwarded-Host: {ORIGIN}\r\n"
            "X-Forwarded-Proto: https\r\n"
            "Authorization: Bearer remote-bearer\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: 5\r\n\r\n"
            "{}"
        ).encode("ascii")
        client.sendall(request)
        client.shutdown(socket.SHUT_WR)
        response = b""
        while True:
            chunk = client.recv(4096)
            if not chunk:
                break
            response += chunk
        client.close()

    assert b" 400 " in response.split(b"\r\n", 1)[0]
    assert b"control.request_invalid" in response


def test_owner_exception_is_sanitized(tmp_path) -> None:
    service = _Service()
    service.raise_marker = True
    with _running_server(tmp_path, service=service) as (server, _service):
        status, _headers_out, payload = _request(
            server,
            "POST",
            "/admin/v1",
            _document("google.accounts.list", {}),
            _headers(),
        )

    assert status == 503
    lowered = payload.lower()
    assert b"private-exception-marker" not in lowered
    assert b"traceback" not in lowered


def test_raw_body_buffer_is_wiped_after_owner_exception(tmp_path) -> None:
    held: list[bytearray] = []

    class FailingPutService(_Service):
        def put_secret(self, principal, session_id, secret, *, upload_claim):
            del principal, session_id, upload_claim
            held.append(secret)
            raise AdminServiceError(_problem("control.owner_unavailable"))

    with _running_server(tmp_path, service=FailingPutService()) as (server, _service):
        _request(
            server,
            "POST",
            "/admin/v1",
            _secret_session_document(),
            _headers(**{"X-Masterjet-Step-Up": _totp()}),
        )
        status, _out, payload = _request(
            server,
            "PUT",
            "/admin/v1/secret-ingress-sessions/ingress-one",
            b"private-marker",
            _headers(**{"Content-Type": "application/octet-stream"}),
        )

    assert status == 503
    assert b"private-marker" not in payload
    assert held == [bytearray()]


def test_shutdown_stops_admission_and_reports_blocked_handler(tmp_path) -> None:
    entered = threading.Event()
    release = threading.Event()

    class BlockingService(_Service):
        def handle(self, principal, request, **kwargs):
            del principal, request, kwargs
            entered.set()
            release.wait(2)
            return {"ok": True}

    with _running_server(tmp_path, service=BlockingService()) as (server, _service):
        result: list[int] = []

        def call() -> None:
            result.append(
                _request(
                    server,
                    "POST",
                    "/admin/v1",
                    _document("google.accounts.list", {}),
                    _headers(),
                )[0]
            )

        worker = threading.Thread(target=call)
        worker.start()
        assert entered.wait(1)
        with pytest.raises(AdminHttpShutdownError, match="shutdown_incomplete"):
            server.drain(0)
        with pytest.raises(AdminHttpShutdownError, match="shutdown_incomplete"):
            server.close_authorities()
        release.set()
        worker.join(2)
        server.drain(1)
        assert result == [200]


def test_drain_observes_handler_claim_before_request_thread_start(
    tmp_path, monkeypatch
) -> None:
    entered = threading.Event()
    release = threading.Event()
    real_start = threading.Thread.start

    def blocked_start(thread: threading.Thread) -> None:
        if (
            thread.name.startswith("Thread-")
            and thread is not threading.current_thread()
        ):
            entered.set()
            assert release.wait(2)
        real_start(thread)

    with _running_server(tmp_path) as (server, _service):
        monkeypatch.setattr(threading.Thread, "start", blocked_start)
        client = threading.Thread(
            target=lambda: _request(
                server,
                "GET",
                "/admin/v1",
                b"",
                _headers(),
            ),
            name="request-client",
        )
        real_start(client)
        assert entered.wait(1)
        with pytest.raises(AdminHttpShutdownError, match="shutdown_incomplete"):
            server.drain(0)
        release.set()
        client.join(2)
        server.drain(1)


@pytest.mark.parametrize("host", ["0.0.0.0", "8.8.8.8", "::"])
def test_server_rejects_nonprivate_or_unspecified_bind(host) -> None:
    with pytest.raises(ValueError, match="control.origin_invalid"):
        AdminHttpServer(
            (host, 0),
            _Service(),
            authority_mode="bearer",
            bearer_verifier=object(),
            access_verifier=None,
            step_up_verifier=object(),
            origin_host=ORIGIN,
        )
