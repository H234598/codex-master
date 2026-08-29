"""Private, bounded HTTP origin adapter for ``MasterjetControlService``."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import math
import re
import socket
import threading
import time
from typing import Final, Protocol, cast
from urllib.parse import quote, unquote_to_bytes
import uuid

from .admin_auth import (
    AdminAuthError,
    CloudflareAccessVerifier,
    MasterjetBearerVerifier,
    TotpStepUpVerifier,
)
from .admin_contracts import (
    AdminContractError,
    AdminPrincipalV1,
    AdminRequestV1,
    HiveProblemV1,
    parse_admin_request,
    public_admin_result,
)
from .admin_service import AdminServiceError, SecretIngressCapabilityV1


MAX_ADMIN_JSON_BYTES: Final[int] = 1_000_000
MAX_ADMIN_SECRET_BYTES: Final[int] = 10_000_000
MAX_ADMIN_RESPONSE_BYTES: Final[int] = 1_000_000
_MAX_HEADERS: Final[int] = 32
_MAX_HEADER_BYTES: Final[int] = 4096
_SESSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_ORIGIN = re.compile(
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z",
    re.ASCII,
)
_INGRESS_PREFIX = "/admin/v1/secret-ingress-sessions/"
_AUTHORITY_MODES = frozenset({"cloudflare", "bearer", "require_both"})
_FLOW_APPLY = {
    "openai.auth-json": "openai.auth.apply",
    "google.oauth-client": "google.oauth-client-import.apply",
    "google-oauth-code": "google.oauth.complete",
}


class _ControlService(Protocol):
    def handle(
        self,
        principal: AdminPrincipalV1,
        request: AdminRequestV1,
        *,
        ingress_session: object | None = None,
        oauth_code: str | None = None,
    ) -> dict[str, object]: ...

    def put_secret(
        self,
        principal: AdminPrincipalV1,
        session_id: str,
        secret: bytes | bytearray | memoryview,
        *,
        upload_claim: object,
    ) -> dict[str, object]: ...

    def reserve_secret_upload(
        self,
        principal: AdminPrincipalV1,
        session_id: str,
        *,
        expected_generation: int,
        idempotency_key: str,
    ) -> object: ...

    def rollback_secret_upload(self, upload_claim: object) -> None: ...


class AdminHttpShutdownError(RuntimeError):
    """Typed incomplete drain; authorities remain live until finalization."""

    def __init__(self) -> None:
        super().__init__("control.http_shutdown_incomplete")


@dataclass(frozen=True, slots=True)
class _FlowGrant:
    subject: str
    account_ref: str
    plan_digest: str
    transaction_id: str | None
    apply_operation: str
    credential_kind: str
    expected_generation: int
    create_idempotency_key: str
    upload_idempotency_key: str | None
    receipt_generation: int | None
    session_id: str
    expires_at: float
    stage: str


class _FlowGrants:
    __slots__ = ("_clock", "_consumed", "_grants", "_lock", "_ttl")

    def __init__(self, clock: Callable[[], float], *, ttl_seconds: int = 120) -> None:
        self._clock = clock
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        self._grants: dict[str, _FlowGrant] = {}
        self._consumed: dict[str, float] = {}

    def add(
        self,
        principal: AdminPrincipalV1,
        request: AdminRequestV1,
        result: Mapping[str, object],
    ) -> None:
        session_id = result.get("id")
        credential_kind = request.arguments.get("credential_kind")
        account_ref = request.arguments.get("account_ref")
        plan_digest = request.plan_digest
        apply_operation = _FLOW_APPLY.get(cast(str, credential_kind))
        expires_at = result.get("expires_at")
        result_digest = result.get("plan_digest")
        result_generation = result.get("expected_generation")
        session_generation = result.get("session_generation")
        if (
            type(session_id) is not str
            or _SESSION.fullmatch(session_id) is None
            or type(account_ref) is not str
            or type(plan_digest) is not str
            or apply_operation is None
            or type(expires_at) not in {int, float}
            or not math.isfinite(cast(float, expires_at))
            or cast(float, expires_at) <= _clock_value(self._clock)
            or result_digest != plan_digest
            or result_generation != request.expected_generation
            or session_generation != request.expected_generation
        ):
            return
        now = _clock_value(self._clock)
        grant = _FlowGrant(
            principal.subject,
            account_ref,
            plan_digest,
            cast(str | None, request.arguments.get("transaction_id")),
            apply_operation,
            cast(str, credential_kind),
            cast(int, request.expected_generation),
            cast(str, request.idempotency_key),
            None,
            None,
            session_id,
            cast(float, expires_at),
            "upload",
        )
        with self._lock:
            self._prune(now)
            self._grants[session_id] = grant

    def claim_upload(
        self,
        subject: str,
        session_id: str,
        *,
        expected_generation: int,
        idempotency_key: str,
    ) -> _FlowGrant | None:
        now = _clock_value(self._clock)
        with self._lock:
            self._prune(now)
            grant = self._grants.get(session_id)
            if (
                grant is None
                or grant.subject != subject
                or grant.stage != "upload"
                or grant.expires_at <= now
                or grant.expected_generation != expected_generation
            ):
                return None
            claimed = replace(
                grant,
                stage="uploading",
                upload_idempotency_key=idempotency_key,
            )
            self._grants[session_id] = claimed
            return claimed

    def finish_upload(self, claimed: _FlowGrant, generation: int) -> None:
        with self._lock:
            grant = self._grants.get(claimed.session_id)
            if grant != claimed or grant.stage != "uploading":
                raise AdminAuthError("authority.step_up_invalid")
            self._grants[claimed.session_id] = replace(
                grant, stage="apply", receipt_generation=generation
            )
            self._consumed[claimed.session_id] = grant.expires_at

    def rollback_upload(self, claimed: _FlowGrant) -> None:
        with self._lock:
            grant = self._grants.get(claimed.session_id)
            if grant == claimed and grant.stage == "uploading":
                self._grants[claimed.session_id] = replace(
                    grant,
                    stage="upload",
                    upload_idempotency_key=None,
                )

    def fail_upload(self, session_id: str) -> None:
        now = _clock_value(self._clock)
        with self._lock:
            self._grants.pop(session_id, None)
            self._consumed[session_id] = now + self._ttl

    def reserve_apply(
        self, subject: str, request: AdminRequestV1
    ) -> SecretIngressCapabilityV1 | None:
        account_ref = request.arguments.get("account_ref")
        now = _clock_value(self._clock)

        def request_matches(grant: _FlowGrant) -> bool:
            if grant.apply_operation == "google.oauth.complete":
                return (
                    grant.transaction_id == request.arguments.get("transaction_id")
                    and request.plan_digest is None
                )
            return grant.plan_digest == request.plan_digest

        with self._lock:
            self._prune(now)
            matches = [
                session_id
                for session_id, grant in self._grants.items()
                if grant.stage == "apply"
                and grant.subject == subject
                and grant.account_ref == account_ref
                and grant.apply_operation == request.operation
                and request_matches(grant)
                and grant.expected_generation == request.expected_generation
                and grant.expires_at > now
            ]
            if len(matches) != 1:
                return None
            grant = self._grants[matches[0]]
            if grant.upload_idempotency_key is None or grant.receipt_generation is None:
                return None
            capability = SecretIngressCapabilityV1(
                grant.session_id,
                grant.subject,
                grant.account_ref,
                grant.apply_operation,
                grant.credential_kind,
                grant.transaction_id,
                grant.plan_digest,
                grant.expected_generation,
                grant.create_idempotency_key,
                grant.upload_idempotency_key,
                request.idempotency_key
                or cast(str, request.arguments.get("transaction_id")),
                grant.expected_generation,
                grant.receipt_generation,
                grant.expires_at,
            )
            self._grants[grant.session_id] = replace(grant, stage="applying")
            return capability

    def finish_apply(self, capability: SecretIngressCapabilityV1) -> None:
        with self._lock:
            grant = self._grants.get(capability.session_id)
            if grant is None or grant.stage != "applying":
                raise AdminAuthError("authority.step_up_invalid")
            self._grants.pop(capability.session_id)
            self._consumed[capability.session_id] = grant.expires_at

    def rollback_apply(self, capability: SecretIngressCapabilityV1) -> None:
        with self._lock:
            grant = self._grants.get(capability.session_id)
            if grant is not None and grant.stage == "applying":
                self._grants[capability.session_id] = replace(grant, stage="apply")

    def fail_apply(self, capability: SecretIngressCapabilityV1) -> None:
        now = _clock_value(self._clock)
        with self._lock:
            self._grants.pop(capability.session_id, None)
            self._consumed[capability.session_id] = now + self._ttl

    def consumed(self, session_id: str) -> bool:
        now = _clock_value(self._clock)
        with self._lock:
            self._prune(now)
            return session_id in self._consumed

    def mark_consumed(self, session_id: str) -> None:
        now = _clock_value(self._clock)
        with self._lock:
            self._consumed[session_id] = now + self._ttl

    def _prune(self, now: float) -> None:
        self._grants = {
            key: grant for key, grant in self._grants.items() if grant.expires_at > now
        }
        self._consumed = {
            key: expires for key, expires in self._consumed.items() if expires > now
        }


class _AdminHandler(BaseHTTPRequestHandler):
    server: AdminHttpServer
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        if self.path != "/admin/v1":
            self._reply_problem(404, "control.route_not_found")
            return
        if not self._boundary_valid():
            return
        try:
            principal = self._authenticate()
        except AdminAuthError as error:
            self._reply_auth_error(error)
            return
        body = self._read_body(MAX_ADMIN_JSON_BYTES, "application/json")
        if body is None:
            return
        try:
            value = json.loads(
                body,
                parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
            )
            request = parse_admin_request(value)
        except (
            AdminContractError,
            UnicodeError,
            ValueError,
            TypeError,
            RecursionError,
        ):
            self._reply_problem(400, "control.request_invalid")
            return
        ingress_session: SecretIngressCapabilityV1 | None = None
        try:
            principal, verified = self._authorize_step_up(principal, request)
            ingress_session = self.server.flow_grants.reserve_apply(
                principal.subject, request
            )
            if ingress_session is not None:
                principal = replace(principal, step_up=True)
            result = self.server.service.handle(
                principal, request, ingress_session=ingress_session
            )
            if ingress_session is not None:
                self.server.flow_grants.finish_apply(ingress_session)
            if verified and request.operation == "secret.ingress.create":
                self.server.flow_grants.add(principal, request, result)
        except AdminAuthError as error:
            if ingress_session is not None:
                self.server.flow_grants.rollback_apply(ingress_session)
            self._reply_auth_error(error)
            return
        except AdminServiceError as error:
            if ingress_session is not None:
                self.server.flow_grants.rollback_apply(ingress_session)
            self._reply_service_error(error)
            return
        except Exception:
            if ingress_session is not None:
                self.server.flow_grants.fail_apply(ingress_session)
            self._reply_problem(503, "control.owner_unavailable")
            return
        self._reply_json(200, self._wire_result(request, result))

    def do_PUT(self) -> None:  # noqa: N802 - stdlib handler API
        session_id = self._ingress_session_id()
        if session_id is None:
            self._reply_problem(404, "control.route_not_found")
            return
        if not self._boundary_valid():
            return
        try:
            principal = self._authenticate()
        except AdminAuthError as error:
            self._reply_auth_error(error)
            return
        if self.server.flow_grants.consumed(session_id):
            self._reply_problem(410, "credential.upload_expired")
            return
        grant: _FlowGrant | None = None
        upload_claim: object | None = None
        body: bytearray | None = None
        try:
            expected_generation = self._uint_header("X-Masterjet-Expected-Generation")
            idempotency_key = self._required_header("Idempotency-Key")
            if self._required_header("X-Masterjet-Operation") != "secret.ingress.put":
                raise AdminAuthError("authority.step_up_invalid")
            grant = self.server.flow_grants.claim_upload(
                principal.subject,
                session_id,
                expected_generation=expected_generation,
                idempotency_key=idempotency_key,
            )
            if grant is None:
                self._reply_problem(410, "credential.upload_expired")
                return
            principal = replace(principal, step_up=True)
            upload_claim = self.server.service.reserve_secret_upload(
                principal,
                session_id,
                expected_generation=expected_generation,
                idempotency_key=idempotency_key,
            )
            body = self._read_body(MAX_ADMIN_SECRET_BYTES, "application/octet-stream")
            if body is None:
                self.server.service.rollback_secret_upload(upload_claim)
                self.server.flow_grants.rollback_upload(grant)
                return
            result = self.server.service.put_secret(
                principal,
                session_id,
                body,
                upload_claim=upload_claim,
            )
            generation = result.get("generation")
            if type(generation) is not int:
                raise AdminAuthError("authority.step_up_invalid")
            self.server.flow_grants.finish_upload(grant, generation)
        except AdminAuthError as error:
            if grant is not None:
                self.server.flow_grants.rollback_upload(grant)
            self._reply_auth_error(error)
            return
        except AdminServiceError as error:
            if upload_claim is not None and body is None:
                try:
                    self.server.service.rollback_secret_upload(upload_claim)
                except AdminServiceError:
                    pass
            if grant is not None:
                self.server.flow_grants.rollback_upload(grant)
            self._reply_service_error(error)
            return
        except Exception:
            if upload_claim is not None and body is None:
                try:
                    self.server.service.rollback_secret_upload(upload_claim)
                except Exception:
                    pass
            if grant is not None:
                self.server.flow_grants.fail_upload(session_id)
            self._reply_problem(503, "control.owner_unavailable")
            return
        finally:
            if isinstance(body, bytearray):
                body[:] = b"\x00" * len(body)
                body.clear()
        self._reply_json(
            200,
            {
                "schema_version": 1,
                "session_id": session_id,
                "account_ref": result.get("account_ref"),
                "state": result.get("state"),
                "generation": generation,
            },
        )

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        self._reply_problem(
            405 if self.path == "/admin/v1" else 404, "control.route_not_found"
        )

    do_DELETE = do_GET
    do_PATCH = do_GET
    do_HEAD = do_GET
    do_OPTIONS = do_GET
    do_TRACE = do_GET
    do_CONNECT = do_GET

    def handle_expect_100(self) -> bool:
        self._reply_problem(417, "control.request_invalid")
        return False

    def send_error(
        self,
        code: int,
        message: str | None = None,
        explain: str | None = None,
    ) -> None:
        """Replace stdlib HTML errors, including arbitrary extension methods."""

        del message, explain
        status = (
            405 if code == 501 and getattr(self, "path", "") == "/admin/v1" else code
        )
        self._reply_problem(status, "control.route_not_found")

    def _authorize_step_up(
        self, principal: AdminPrincipalV1, request: AdminRequestV1
    ) -> tuple[AdminPrincipalV1, bool]:
        code = self._optional_header("X-Masterjet-Step-Up")
        if code is not None:
            self.server.step_up_verifier.verify(principal.subject, code)
            return replace(principal, step_up=True), True
        return principal, False

    def _uint_header(self, name: str) -> int:
        value = self._required_header(name)
        if re.fullmatch(r"[0-9]+", value) is None:
            raise AdminAuthError("authority.step_up_invalid")
        number = int(value)
        if number > 2**63 - 1:
            raise AdminAuthError("authority.step_up_invalid")
        return number

    def _authenticate(self) -> AdminPrincipalV1:
        mode = self.server.authority_mode
        cloudflare: AdminPrincipalV1 | None = None
        bearer: AdminPrincipalV1 | None = None
        if mode in {"cloudflare", "require_both"}:
            assertion = self._required_header("Cf-Access-Jwt-Assertion")
            access_authority = self.server.access_verifier
            if access_authority is None:
                raise AdminAuthError("authority.configuration_invalid")
            cloudflare = access_authority.verify(assertion)
        if mode in {"bearer", "require_both"}:
            authorization = self._required_header("Authorization")
            if not authorization.startswith("Bearer ") or authorization.count(" ") != 1:
                raise AdminAuthError("authority.identity_invalid")
            bearer_authority = self.server.bearer_verifier
            if bearer_authority is None:
                raise AdminAuthError("authority.configuration_invalid")
            bearer = bearer_authority.verify(authorization[7:])
        if mode == "cloudflare":
            return cast(AdminPrincipalV1, cloudflare)
        if mode == "bearer":
            return cast(AdminPrincipalV1, bearer)
        if cloudflare is None or bearer is None:
            raise AdminAuthError("authority.configuration_invalid")
        scopes = tuple(scope for scope in cloudflare.scopes if scope in bearer.scopes)
        return AdminPrincipalV1(
            cloudflare.subject,
            scopes,
            "cloudflare-access.masterjet-bearer",
            False,
        )

    def _boundary_valid(self) -> bool:
        try:
            peer = ipaddress.ip_address(self.client_address[0])
            if str(peer) not in self.server.trusted_proxy_addresses:
                raise ValueError
            if len(self.headers) > _MAX_HEADERS:
                raise ValueError
            if any(
                len(name.encode("ascii")) + len(value.encode("ascii"))
                > _MAX_HEADER_BYTES
                for name, value in self.headers.items()
            ):
                raise ValueError
            if self._required_header("Host") != self.server.origin_host:
                raise ValueError
            if self._required_header("X-Forwarded-Host") != self.server.origin_host:
                raise ValueError
            if self._required_header("X-Forwarded-Proto") != "https":
                raise ValueError
            if self.headers.get_all("Forwarded"):
                raise ValueError
        except (AdminAuthError, UnicodeError, ValueError):
            self._reply_problem(400, "control.origin_invalid")
            return False
        return True

    def _read_body(self, maximum: int, content_type: str) -> bytearray | None:
        body = bytearray()
        view: memoryview | None = None
        accepted = False
        try:
            if self.headers.get_all("Transfer-Encoding"):
                raise ValueError
            if (
                self._required_header("Content-Type").split(";", 1)[0].strip().lower()
                != content_type
            ):
                raise ValueError
            raw_lengths = self.headers.get_all("Content-Length") or []
            if len(raw_lengths) != 1 or re.fullmatch(r"[0-9]+", raw_lengths[0]) is None:
                self._reply_problem(411, "control.request_invalid")
                return None
            length = int(raw_lengths[0])
            if length <= 0:
                raise ValueError
            if length > maximum:
                self._reply_problem(413, "control.request_too_large")
                return None
            body = bytearray(length)
            view = memoryview(body)
            offset = 0
            while offset < length:
                count = self.rfile.readinto(view[offset:])
                if not count:
                    break
                offset += count
            if offset != length:
                raise ValueError
            accepted = True
            return body
        except AdminAuthError:
            self._reply_problem(400, "control.request_invalid")
        except (OSError, TypeError, UnicodeError, ValueError):
            self._reply_problem(400, "control.request_invalid")
        finally:
            if view is not None:
                view.release()
            if not accepted:
                body[:] = b"\x00" * len(body)
                body.clear()
        return None

    def _ingress_session_id(self) -> str | None:
        if not self.path.startswith(_INGRESS_PREFIX):
            return None
        segment = self.path[len(_INGRESS_PREFIX) :]
        try:
            raw = unquote_to_bytes(segment)
            session_id = raw.decode("ascii")
        except (UnicodeError, ValueError):
            return None
        if (
            not session_id
            or "/" in session_id
            or "%" in session_id
            or "?" in session_id
            or "#" in session_id
            or _SESSION.fullmatch(session_id) is None
            or quote(session_id, safe="") != segment
        ):
            return None
        return session_id

    def _required_header(self, name: str) -> str:
        values = self.headers.get_all(name) or []
        if len(values) != 1 or not values[0] or "\r" in values[0] or "\n" in values[0]:
            raise AdminAuthError("authority.identity_invalid")
        return values[0]

    def _optional_header(self, name: str) -> str | None:
        values = self.headers.get_all(name) or []
        if not values:
            return None
        if len(values) != 1 or not values[0] or len(values[0]) > 128:
            raise AdminAuthError("authority.step_up_invalid")
        return values[0]

    def _reply_service_error(self, error: AdminServiceError) -> None:
        code = error.problem.code
        if code == "authority.step_up_required":
            self._reply_problem(403, "control.step_up_required")
            return
        self._reply_json(_status_for_code(code), public_admin_result(error.problem))

    def _wire_result(
        self, request: AdminRequestV1, result: Mapping[str, object]
    ) -> dict[str, object]:
        del request
        return {"schema_version": 1, **result}

    def _reply_auth_error(self, error: AdminAuthError) -> None:
        status = 401 if error.code == "authority.identity_invalid" else 403
        self._reply_problem(status, error.code)

    def _reply_problem(self, status: int, code: str) -> None:
        if code == "control.step_up_required":
            severity = "warning"
            title = "Step-up required"
            detail = "Additional authentication is required."
            effect = "Operation is paused."
            action = "Complete step-up authentication."
        else:
            severity = "error"
            title = "Request failed"
            detail = "Request could not be completed"
            effect = "No action was started"
            action = "Review access and retry"
        problem = HiveProblemV1(
            code=code,
            severity=severity,
            title=title,
            detail=detail,
            effect=effect,
            action=action,
            retryable=False,
            retry_after_seconds=None,
            correlation_id="corr-" + uuid.uuid4().hex,
            occurred_at=datetime.now(UTC),
        )
        self._reply_json(status, public_admin_result(problem))

    def _reply_json(self, status: int, value: Mapping[str, object]) -> None:
        try:
            payload = json.dumps(
                dict(value),
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
            ).encode("ascii")
            if len(payload) > MAX_ADMIN_RESPONSE_BYTES:
                raise ValueError
        except (TypeError, ValueError, RecursionError):
            if status == 503:
                payload = b'{"schema_version":1,"code":"control.owner_unavailable"}'
            else:
                self._reply_problem(503, "control.owner_unavailable")
                return
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            if self.command != "HEAD":
                self.wfile.write(payload)
        except OSError:
            return

    def log_message(self, _format: str, *_args: object) -> None:
        return


class AdminHttpServer(ThreadingHTTPServer):
    """Threaded HTTP origin with explicit private bind and auth authority."""

    daemon_threads = False
    block_on_close = False
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        service: _ControlService,
        *,
        authority_mode: str,
        bearer_verifier: MasterjetBearerVerifier | None,
        access_verifier: CloudflareAccessVerifier | None,
        step_up_verifier: TotpStepUpVerifier,
        origin_host: str,
        clock: Callable[[], float] = time.monotonic,
        trusted_proxy_addresses: tuple[str, ...] | None = None,
        socket_timeout_seconds: float = 10.0,
    ) -> None:
        host = _bind_host(address)
        if authority_mode not in _AUTHORITY_MODES:
            raise ValueError("authority.configuration_invalid")
        if authority_mode in {"bearer", "require_both"} and bearer_verifier is None:
            raise ValueError("authority.configuration_invalid")
        if authority_mode in {"cloudflare", "require_both"} and access_verifier is None:
            raise ValueError("authority.configuration_invalid")
        if (
            not callable(getattr(service, "handle", None))
            or not callable(getattr(service, "put_secret", None))
            or not callable(getattr(service, "reserve_secret_upload", None))
            or not callable(getattr(service, "rollback_secret_upload", None))
        ):
            raise ValueError("control.owner_unavailable")
        if not callable(getattr(step_up_verifier, "verify", None)):
            raise ValueError("authority.configuration_invalid")
        if type(origin_host) is not str or _ORIGIN.fullmatch(origin_host) is None:
            raise ValueError("control.origin_invalid")
        if (
            type(socket_timeout_seconds) not in {int, float}
            or not math.isfinite(socket_timeout_seconds)
            or not 1 <= socket_timeout_seconds <= 30
        ):
            raise ValueError("control.origin_invalid")
        if trusted_proxy_addresses is None:
            if not host.is_loopback:
                raise ValueError("control.origin_invalid")
            trusted_proxy_addresses = (str(host),)
        trusted_proxies = _trusted_proxies(trusted_proxy_addresses)
        self.address_family = socket.AF_INET6 if host.version == 6 else socket.AF_INET
        self.service = service
        self.authority_mode = authority_mode
        self.bearer_verifier = bearer_verifier
        self.access_verifier = access_verifier
        self.step_up_verifier = step_up_verifier
        self.origin_host = origin_host
        self.trusted_proxy_addresses = trusted_proxies
        self.flow_grants = _FlowGrants(clock)
        self.socket_timeout_seconds = float(socket_timeout_seconds)
        self._drain_condition = threading.Condition()
        self._active_handlers = 0
        self._accepting = True
        self._authorities_closed = False
        super().__init__(address, _AdminHandler)

    def get_request(self) -> tuple[socket.socket, object]:
        connection, client_address = super().get_request()
        connection.settimeout(self.socket_timeout_seconds)
        return connection, client_address

    def verify_request(
        self,
        request: socket.socket | tuple[bytes, socket.socket],
        client_address: object,
    ) -> bool:
        del request, client_address
        return True

    def process_request(
        self,
        request: socket.socket | tuple[bytes, socket.socket],
        client_address: object,
    ) -> None:
        with self._drain_condition:
            if not self._accepting:
                self.shutdown_request(request)
                return
            self._active_handlers += 1
        try:
            super().process_request(request, client_address)
        except BaseException:
            with self._drain_condition:
                self._active_handlers -= 1
                self._drain_condition.notify_all()
            raise

    def process_request_thread(
        self,
        request: socket.socket | tuple[bytes, socket.socket],
        client_address: object,
    ) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._drain_condition:
                self._active_handlers -= 1
                self._drain_condition.notify_all()

    def server_close(self) -> None:
        with self._drain_condition:
            if self._active_handlers:
                raise AdminHttpShutdownError
        super().server_close()

    def shutdown(self) -> None:
        with self._drain_condition:
            self._accepting = False
        super().shutdown()

    def drain(self, timeout_seconds: float) -> None:
        if (
            type(timeout_seconds) not in {int, float}
            or not math.isfinite(timeout_seconds)
            or timeout_seconds < 0
        ):
            raise ValueError("control.http_shutdown_invalid")
        deadline = time.monotonic() + float(timeout_seconds)
        with self._drain_condition:
            self._accepting = False
            while self._active_handlers:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AdminHttpShutdownError
                self._drain_condition.wait(remaining)

    def close_authorities(self) -> None:
        with self._drain_condition:
            if self._active_handlers or self._accepting:
                raise AdminHttpShutdownError
            if self._authorities_closed:
                return
            self._authorities_closed = True
        if self.bearer_verifier is not None:
            self.bearer_verifier.close()
        self.step_up_verifier.close()


def _bind_host(address: object) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        if type(address) is not tuple or len(address) != 2:
            raise ValueError
        host = ipaddress.ip_address(address[0])
        port = address[1]
        if (
            not (host.is_loopback or host.is_private)
            or host.is_unspecified
            or host.is_multicast
            or type(port) is not int
            or not 0 <= port <= 65535
        ):
            raise ValueError
        return host
    except (TypeError, ValueError):
        raise ValueError("control.origin_invalid") from None


def _clock_value(clock: Callable[[], float]) -> float:
    value = clock()
    if type(value) not in {int, float} or not math.isfinite(value) or value < 0:
        raise AdminAuthError("authority.configuration_invalid")
    return float(value)


def _trusted_proxies(values: object) -> frozenset[str]:
    try:
        if type(values) is not tuple or not 1 <= len(values) <= 16:
            raise ValueError
        result = frozenset(str(ipaddress.ip_address(value)) for value in values)
        if len(result) != len(values) or any(
            ipaddress.ip_address(value).is_unspecified
            or ipaddress.ip_address(value).is_multicast
            for value in result
        ):
            raise ValueError
        return result
    except (TypeError, ValueError):
        raise ValueError("control.origin_invalid") from None


def _status_for_code(code: str) -> int:
    if code in {"authority.scope_denied", "authority.step_up_required"}:
        return 403
    if code in {"credential.upload_expired", "control.plan_stale"}:
        return 410
    if code == "control.request_too_large":
        return 413
    if code.startswith("control.request_"):
        return 400
    if code == "control.owner_unavailable":
        return 503
    return 409
