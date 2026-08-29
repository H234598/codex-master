from __future__ import annotations

from contextlib import contextmanager
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
)
from test_admin_service import service_at


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
        self.capabilities: list[object] = []

    def handle(
        self,
        principal: AdminPrincipalV1,
        request: AdminRequestV1,
        *,
        ingress_session=None,
        oauth_code=None,
    ):
        del oauth_code
        self.calls.append((principal, request))
        if ingress_session is not None:
            self.capabilities.append(ingress_session)
        if self.raise_marker:
            raise RuntimeError("private-exception-marker")
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
            return {
                "id": "ingress-one",
                "account_ref": "google-one",
                "state": "pending",
            }
        return {
            "operation": request.operation,
            "step_up": principal.step_up,
        }

    def put_secret(self, principal: AdminPrincipalV1, session_id: str, secret):
        if not principal.step_up:
            raise AdminDenied(_problem("authority.step_up_required"))
        if session_id in self.consumed:
            raise AdminServiceError(_problem("credential.upload_expired"))
        self.consumed.add(session_id)
        self.secrets.append(bytes(secret))
        return {"id": session_id, "account_ref": "google-one", "state": "consumed"}


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
        totp = TotpStepUpVerifier.from_fd(totp_fd, clock=lambda: NOW, skew_steps=0)
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
        clock=lambda: NOW,
        trusted_proxy_addresses=trusted_proxy_addresses,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, service
    finally:
        server.shutdown()
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
    assert replay == 403
    assert owners.secret_ingress.resolve_calls == 1
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


def test_google_oauth_code_crosses_only_typed_raw_ingress_boundary(tmp_path) -> None:
    service, owners = service_at()
    session = _document(
        "secret.ingress.create",
        {
            "account_ref": "google-one",
            "credential_kind": "google-oauth-code",
            "plan_id": "transaction-one",
        },
        expected_generation=4,
        idempotency_key="idem-oauth-code",
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


def test_oversized_content_length_is_rejected_without_owner_call(tmp_path) -> None:
    with _running_server(tmp_path) as (server, service):
        status, _headers_out, payload = _request(
            server,
            "POST",
            "/admin/v1",
            b"x" * (MAX_ADMIN_JSON_BYTES + 1),
            _headers(),
        )

    assert status == 413
    assert json.loads(payload)["code"] == "control.request_too_large"
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
