from __future__ import annotations

import base64
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
import http.client
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import venv

from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
import pytest

import codex_master.admin_assembly as admin_assembly
from codex_master.admin_auth import MasterjetBearerVerifier, TotpStepUpVerifier
from codex_master.admin_contracts import AdminPrincipalV1, AdminRequestV1
from codex_master.admin_daemon import (
    AdminDaemon,
    AdminDaemonShutdownError,
    AdminDaemonStartupError,
    CloudflareJwksFetchError,
    CloudflareJwksFetcher,
    JwksRefreshShutdownError,
    RefreshingCloudflareAccessVerifier,
)
from codex_master.admin_assembly import CredentialQuotaCollector, assemble_admin_runtime
from codex_master.admin_http import AdminHttpServer
from codex_master.admin_service import MasterjetControlService
from codex_master.google_oauth_authorization import GoogleOAuthProfileIdV1
from codex_master.google_oauth_session import (
    GoogleOAuthClientMaterialV1,
    GoogleOAuthSessionError,
)


ISSUER = "https://team.cloudflareaccess.com"
AUDIENCE = "application-audience"
NOW = 2_000_000_000


class _Socket:
    def __init__(
        self,
        service: MasterjetControlService,
        events: list[str],
        *,
        close_error: Exception | None = None,
    ) -> None:
        self.service = service
        self._events = events
        self._close_error = close_error

    def start(self) -> None:
        self._events.append("socket-bound")

    def close(self) -> None:
        self._events.append("socket-closed")
        if self._close_error is not None:
            raise self._close_error


class _Http:
    def __init__(self, service: MasterjetControlService, events: list[str]) -> None:
        self.service = service
        self._events = events
        self._stopped = threading.Event()
        self._serving = threading.Event()

    def serve_forever(self, *, poll_interval: float = 0.5) -> None:
        del poll_interval
        self._events.append("http-serving")
        self._serving.set()
        self._stopped.wait()

    def wait_serving(self, timeout_seconds: float) -> bool:
        return self._serving.wait(timeout_seconds)

    def shutdown(self) -> None:
        self._events.append("http-admission-stopped")
        self._stopped.set()

    def drain(self, timeout_seconds: float) -> None:
        assert timeout_seconds >= 0
        self._events.append("http-drained")

    def server_close(self) -> None:
        self._events.append("http-closed")

    def close_authorities(self) -> None:
        self._events.append("authorities-closed")


class _Refresher:
    def __init__(self, events: list[str]) -> None:
        self._events = events

    def start(self) -> None:
        self._events.append("jwks-started")

    def close(self, timeout_seconds: float) -> None:
        assert timeout_seconds >= 0
        self._events.append("jwks-closed")


def _daemon(
    service: MasterjetControlService,
    events: list[str],
    *,
    http_factory=None,
    socket_close_error: Exception | None = None,
    notifications: list[str] | None = None,
) -> AdminDaemon:
    def make_socket(candidate: MasterjetControlService) -> _Socket:
        return _Socket(candidate, events, close_error=socket_close_error)

    def make_http(candidate: MasterjetControlService) -> _Http:
        return _Http(candidate, events)

    return AdminDaemon(
        service,
        socket_factory=make_socket,
        http_factory=make_http if http_factory is None else http_factory,
        jwks_refresher=_Refresher(events),
        notifier=(notifications.append if notifications is not None else None),
        shutdown_timeout_seconds=0.5,
    )


def test_readiness_cannot_race_a_partially_bound_transport(
    service: MasterjetControlService,
) -> None:
    """Production break: systemd may route traffic while only AF_UNIX is bound."""

    events: list[str] = []
    notifications: list[str] = []
    entered = threading.Event()
    release = threading.Event()

    def make_http(candidate: MasterjetControlService) -> _Http:
        entered.set()
        assert release.wait(1)
        events.append("http-bound")
        return _Http(candidate, events)

    daemon = _daemon(
        service,
        events,
        http_factory=make_http,
        notifications=notifications,
    )
    failure: list[BaseException] = []

    def start() -> None:
        try:
            daemon.start()
        except BaseException as error:
            failure.append(error)

    thread = threading.Thread(target=start)
    thread.start()
    assert entered.wait(1)
    assert daemon.ready is False
    assert notifications == []
    release.set()
    thread.join(1)
    assert not thread.is_alive()
    assert failure == []
    assert daemon.ready is True
    assert notifications == ["READY=1"]
    daemon.stop()


def test_immediate_http_serve_failure_never_publishes_readiness(
    service: MasterjetControlService,
) -> None:
    """I1 break: a dead HTTP loop must never be announced READY to systemd."""

    events: list[str] = []
    notifications: list[str] = []
    failed = threading.Event()

    class FailingHttp(_Http):
        def serve_forever(self, *, poll_interval: float = 0.5) -> None:
            del poll_interval
            failed.set()
            raise RuntimeError("control.http_serve_failed")

    def notify(message: str) -> None:
        assert failed.wait(1)
        notifications.append(message)

    daemon = AdminDaemon(
        service,
        socket_factory=lambda candidate: _Socket(candidate, events),
        http_factory=lambda candidate: FailingHttp(candidate, events),
        notifier=notify,
        shutdown_timeout_seconds=0.2,
    )

    with pytest.raises(AdminDaemonStartupError):
        daemon.start()

    assert notifications == []
    assert daemon.ready is False


def test_http_failure_during_ready_notification_revokes_readiness(
    service: MasterjetControlService,
) -> None:
    """I1 break: a serve failure racing READY must publish an immediate revoke."""

    events: list[str] = []
    notifications: list[str] = []
    fail = threading.Event()
    failed = threading.Event()

    class FailingAfterBindHttp(_Http):
        def serve_forever(self, *, poll_interval: float = 0.5) -> None:
            del poll_interval
            self._serving.set()
            assert fail.wait(1)
            failed.set()
            raise RuntimeError("control.http_serve_failed")

    def notify(message: str) -> None:
        if message == "READY=1":
            fail.set()
            assert failed.wait(1)
        notifications.append(message)

    daemon = AdminDaemon(
        service,
        socket_factory=lambda candidate: _Socket(candidate, events),
        http_factory=lambda candidate: FailingAfterBindHttp(candidate, events),
        notifier=notify,
        shutdown_timeout_seconds=0.2,
    )

    with pytest.raises(AdminDaemonStartupError):
        daemon.start()

    assert daemon.ready is False
    assert notifications == ["READY=1", "STOPPING=1"]


def test_http_bind_failure_rolls_back_only_the_owned_socket(
    service: MasterjetControlService,
) -> None:
    """Production break: a failed private origin can leave a live local socket."""

    events: list[str] = []

    def fail_http(_candidate: MasterjetControlService) -> _Http:
        raise OSError("bind unavailable")

    daemon = _daemon(service, events, http_factory=fail_http)

    with pytest.raises(AdminDaemonStartupError, match="control.admin_startup_failed"):
        daemon.start()

    assert events == ["socket-bound", "socket-closed"]
    assert daemon.ready is False


def test_partial_start_rollback_has_one_deadline_and_reports_live_cleanup(
    service: MasterjetControlService,
) -> None:
    """I2 break: a blocked rollback must not hang or erase its live resource."""

    entered = threading.Event()
    release = threading.Event()

    class BlockingSocket(_Socket):
        def close(self) -> None:
            entered.set()
            release.wait()

    daemon = AdminDaemon(
        service,
        socket_factory=lambda candidate: BlockingSocket(candidate, []),
        http_factory=lambda _candidate: (_ for _ in ()).throw(OSError("bind")),
        shutdown_timeout_seconds=0.05,
    )
    captured: list[BaseException] = []

    def start() -> None:
        try:
            daemon.start()
        except BaseException as error:
            captured.append(error)

    worker = threading.Thread(target=start, daemon=True)
    before = time.monotonic()
    worker.start()
    try:
        assert entered.wait(1)
        worker.join(0.2)
        assert not worker.is_alive()
        assert time.monotonic() - before < 0.3
        assert len(captured) == 1
        assert "control.socket_shutdown_incomplete" in str(captured[0])
        assert daemon.incomplete_resources == ("socket",)
    finally:
        release.set()
        worker.join(1)
    daemon.stop()
    assert daemon.incomplete_resources == ()


def test_both_adapters_receive_the_one_exact_service_instance(
    service: MasterjetControlService,
) -> None:
    """Production break: separate factories split idempotency and owner state."""

    events: list[str] = []
    seen: list[MasterjetControlService] = []

    def make_socket(candidate: MasterjetControlService) -> _Socket:
        seen.append(candidate)
        return _Socket(candidate, events)

    def make_http(candidate: MasterjetControlService) -> _Http:
        seen.append(candidate)
        return _Http(candidate, events)

    daemon = AdminDaemon(
        service,
        socket_factory=make_socket,
        http_factory=make_http,
        shutdown_timeout_seconds=0.5,
    )
    daemon.start()
    daemon.stop()

    assert seen == [service, service]
    assert all(candidate is service for candidate in seen)


def test_sigterm_stops_admission_then_finishes_all_owned_lifecycles(
    service: MasterjetControlService,
) -> None:
    """Production break: SIGTERM can exit with listeners or authorities still live."""

    events: list[str] = []
    notifications: list[str] = []
    daemon = _daemon(service, events, notifications=notifications)
    sender_evidence: list[bool] = []

    def terminate_when_ready() -> None:
        ready = daemon.wait_ready(1)
        sender_evidence.append(ready)
        if ready:
            os.kill(os.getpid(), signal.SIGTERM)
            signal_observed = daemon._stop_requested.wait(1)
            sender_evidence.append(signal_observed)
            if signal_observed:
                return
        daemon.request_stop()

    sender = threading.Thread(target=terminate_when_ready)
    sender.start()
    assert daemon.run() == 0
    sender.join(1)
    assert not sender.is_alive()
    assert sender_evidence == [True, True]
    assert notifications == ["READY=1", "STOPPING=1"]
    assert "http-admission-stopped" in events
    assert "socket-closed" in events
    assert "http-drained" in events
    assert "http-closed" in events
    assert "authorities-closed" in events
    assert "jwks-closed" in events


def test_blocked_socket_shutdown_is_not_reported_as_success(
    service: MasterjetControlService,
) -> None:
    """Production break: an incomplete socket worker was previously easy to mask."""

    events: list[str] = []
    daemon = _daemon(
        service,
        events,
        socket_close_error=RuntimeError("control.socket_shutdown_incomplete"),
    )
    daemon.start()

    with pytest.raises(AdminDaemonShutdownError) as captured:
        daemon.stop()

    assert "control.socket_shutdown_incomplete" in str(captured.value)
    assert "http-closed" in events
    assert "authorities-closed" in events
    assert "jwks-closed" in events
    assert daemon.ready is False
    assert daemon.incomplete_resources == ("socket",)


def test_permanently_blocked_socket_close_cannot_consume_owner_deadline(
    service: MasterjetControlService,
) -> None:
    """I3 break: synchronous socket close can prevent every later cleanup step."""

    events: list[str] = []
    entered = threading.Event()
    release = threading.Event()

    class BlockingSocket(_Socket):
        def close(self) -> None:
            entered.set()
            release.wait()

    daemon = AdminDaemon(
        service,
        socket_factory=lambda candidate: BlockingSocket(candidate, events),
        http_factory=lambda candidate: _Http(candidate, events),
        jwks_refresher=_Refresher(events),
        shutdown_timeout_seconds=0.05,
    )
    daemon.start()
    captured: list[BaseException] = []

    def stop() -> None:
        try:
            daemon.stop()
        except BaseException as error:
            captured.append(error)

    worker = threading.Thread(target=stop, daemon=True)
    before = time.monotonic()
    worker.start()
    try:
        assert entered.wait(1)
        worker.join(0.2)
        assert not worker.is_alive()
        assert time.monotonic() - before < 0.3
        assert len(captured) == 1
        assert isinstance(captured[0], AdminDaemonShutdownError)
        assert "http-closed" in events
        assert "authorities-closed" in events
        assert "jwks-closed" in events
    finally:
        release.set()
        worker.join(1)
    daemon.stop()
    assert daemon.incomplete_resources == ()


def _private_fd(tmp_path: Path, name: str, payload: bytes) -> int:
    path = tmp_path / name
    path.write_bytes(payload)
    path.chmod(0o600)
    return os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)


def test_daemon_does_not_publish_an_unauthenticated_health_route(
    tmp_path: Path,
    service: MasterjetControlService,
) -> None:
    """Production break: a health shortcut can bypass the HTTP auth boundary."""

    bearer_fd = _private_fd(tmp_path, "bearer", b"private-bearer")
    totp_fd = _private_fd(
        tmp_path,
        "totp",
        base64.b32encode(b"12345678901234567890"),
    )
    try:
        bearer = MasterjetBearerVerifier.from_fd(
            bearer_fd,
            subject="admin-client",
            scopes=("fleet.read",),
        )
        totp = TotpStepUpVerifier.from_fd(
            totp_fd,
            clock=lambda: NOW,
            replay_state_path=tmp_path / "totp-state",
        )
    finally:
        os.close(bearer_fd)
        os.close(totp_fd)
    http_server: list[AdminHttpServer] = []

    def make_http(candidate: MasterjetControlService) -> AdminHttpServer:
        server = AdminHttpServer(
            ("127.0.0.1", 0),
            candidate,
            authority_mode="bearer",
            bearer_verifier=bearer,
            access_verifier=None,
            step_up_verifier=totp,
            origin_host="admin.internal",
        )
        http_server.append(server)
        return server

    daemon = AdminDaemon(
        service,
        socket_factory=lambda candidate: _Socket(candidate, []),
        http_factory=make_http,
        shutdown_timeout_seconds=1,
    )
    daemon.start()
    connection = http.client.HTTPConnection(*http_server[0].server_address, timeout=1)
    connection.request("GET", "/health")
    response = connection.getresponse()
    response.read()
    connection.close()
    daemon.stop()

    assert response.status == 404


class _Response:
    def __init__(
        self,
        payload: bytes,
        *,
        status: int = 200,
        content_type: str = "application/json",
        url: str = f"{ISSUER}/cdn-cgi/access/certs",
    ) -> None:
        self._payload = payload
        self.status = status
        self.headers = {
            "Content-Type": content_type,
            "Content-Length": str(len(payload)),
        }
        self._url = url

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_values: object) -> None:
        return None

    def geturl(self) -> str:
        return self._url

    def read(self, maximum: int) -> bytes:
        return self._payload[:maximum]


def test_jwks_fetch_uses_only_the_configured_team_certs_url_and_fixed_bounds() -> None:
    """Production break: attacker-controlled JWT metadata can redirect JWKS fetches."""

    calls: list[tuple[str, float]] = []
    payload = b'{"keys":[{"kid":"one"}]}'

    def open_response(request, *, timeout: float):
        calls.append((request.full_url, timeout))
        return _Response(payload)

    fetcher = CloudflareJwksFetcher(
        "team.cloudflareaccess.com",
        open_response=open_response,
    )

    assert fetcher() == {"keys": [{"kid": "one"}]}
    assert calls == [("https://team.cloudflareaccess.com/cdn-cgi/access/certs", 5.0)]


@pytest.mark.parametrize(
    ("response", "team_domain"),
    [
        (_Response(b"{}", status=503), "team.cloudflareaccess.com"),
        (_Response(b"{}", content_type="text/html"), "team.cloudflareaccess.com"),
        (
            _Response(
                b"{}",
                url="https://attacker.invalid/cdn-cgi/access/certs",
            ),
            "team.cloudflareaccess.com",
        ),
        (_Response(b"x" * 65_537), "team.cloudflareaccess.com"),
        (_Response(b'{"keys":[],"keys":[]}'), "team.cloudflareaccess.com"),
        (_Response(b"{}"), "https://team.cloudflareaccess.com"),
        (_Response(b"{}"), "team.cloudflareaccess.com/path"),
    ],
)
def test_jwks_fetch_fails_closed_on_response_or_domain_contract_break(
    response: _Response,
    team_domain: str,
) -> None:
    """Production break: malformed, redirected, or oversized keysets can become trust."""

    with pytest.raises(CloudflareJwksFetchError):
        fetcher = CloudflareJwksFetcher(
            team_domain,
            open_response=lambda _request, **_values: response,
        )
        fetcher()


def _b64(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _jwk(private_key, kid: str) -> dict[str, str]:
    numbers = private_key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": _b64(numbers.n),
        "e": _b64(numbers.e),
    }


def _token(private_key, kid: str) -> str:
    return jwt.encode(
        {
            "iss": ISSUER,
            "aud": [AUDIENCE],
            "sub": "operator-one",
            "iat": NOW - 10,
            "nbf": NOW - 10,
            "exp": NOW + 120,
        },
        private_key,
        algorithm="RS256",
        headers={"kid": kid},
    )


def test_unknown_kid_refresh_keeps_current_and_previous_keys_as_lkg() -> None:
    """Production break: rotation can reject live tokens or erase the last good set."""

    previous = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    current = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    loads: list[int] = []

    def load() -> dict[str, object]:
        loads.append(1)
        return {"keys": [_jwk(current, "current")]}

    verifier = RefreshingCloudflareAccessVerifier(
        issuer=ISSUER,
        audience=AUDIENCE,
        initial_jwks={"keys": [_jwk(previous, "previous")]},
        loader=load,
        principal_resolver=lambda _subject, _claims: ("fleet.read",),
        clock=lambda: NOW,
        refresh_interval_seconds=60,
        refresh_timeout_seconds=0.5,
    )

    assert verifier.verify(_token(current, "current")).subject == "operator-one"
    assert verifier.verify(_token(previous, "previous")).subject == "operator-one"
    assert loads == [1]
    assert verifier.jwks_state() == {
        "current_kids": ("current",),
        "previous_kids": ("previous",),
        "refreshed_at": float(NOW),
    }


def test_failed_jwks_refresh_never_destroys_last_known_good() -> None:
    """Production break: a transient Cloudflare failure can empty all trusted keys."""

    current = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verifier = RefreshingCloudflareAccessVerifier(
        issuer=ISSUER,
        audience=AUDIENCE,
        initial_jwks={"keys": [_jwk(current, "current")]},
        loader=lambda: {"keys": []},
        principal_resolver=lambda _subject, _claims: ("fleet.read",),
        clock=lambda: NOW,
        refresh_interval_seconds=60,
        refresh_timeout_seconds=0.5,
    )

    assert verifier.refresh() is False
    assert verifier.verify(_token(current, "current")).subject == "operator-one"
    assert verifier.jwks_state()["current_kids"] == ("current",)


def test_unknown_kids_share_one_refresh_and_one_global_negative_cooldown() -> None:
    """I4 break: random unknown kids must not serialize repeated network fetches."""

    current = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    unknown = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    loads = 0
    lock = threading.Lock()

    def load() -> dict[str, object]:
        nonlocal loads
        with lock:
            loads += 1
        time.sleep(0.03)
        return {"keys": [_jwk(current, "current")]}

    verifier = RefreshingCloudflareAccessVerifier(
        issuer=ISSUER,
        audience=AUDIENCE,
        initial_jwks={"keys": [_jwk(current, "current")]},
        loader=load,
        principal_resolver=lambda _subject, _claims: ("fleet.read",),
        clock=lambda: NOW,
        refresh_interval_seconds=60,
        refresh_timeout_seconds=0.5,
        unknown_kid_cooldown_seconds=0.5,
    )
    tokens = [_token(unknown, f"missing-{index}") for index in range(8)]

    def denied(token: str) -> bool:
        with pytest.raises(Exception, match="authority.identity_invalid"):
            verifier.verify(token)
        return True

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert all(pool.map(denied, tokens))
    denied(_token(unknown, "later-missing"))

    assert loads == 1


def test_blocked_periodic_jwks_worker_has_bounded_honest_shutdown() -> None:
    """Production break: shutdown can hang forever or claim a stuck fetcher stopped."""

    current = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    entered = threading.Event()
    release = threading.Event()

    def load() -> dict[str, object]:
        entered.set()
        assert release.wait(1)
        return {"keys": [_jwk(current, "current")]}

    verifier = RefreshingCloudflareAccessVerifier(
        issuer=ISSUER,
        audience=AUDIENCE,
        initial_jwks={"keys": [_jwk(current, "current")]},
        loader=load,
        principal_resolver=lambda _subject, _claims: ("fleet.read",),
        clock=lambda: NOW,
        refresh_interval_seconds=0.01,
        refresh_timeout_seconds=0.5,
    )
    verifier.start()
    assert entered.wait(1)

    with pytest.raises(JwksRefreshShutdownError):
        verifier.close(0.01)

    release.set()
    verifier.close(1)


def _credential(path: Path, payload: bytes) -> None:
    path.write_bytes(payload)
    path.chmod(0o600)


def _quota_evidence_payload(remaining: int) -> bytes:
    return json.dumps(
        {
            "schema_version": 1,
            "accounts": [
                {
                    "account_ref": "google-one",
                    "remaining": remaining,
                    "observed_at": "2026-08-29T20:00:00Z",
                    "source": "cloudresourcemanager",
                    "inventory_generation": 4,
                    "inventory_fingerprint": "sha256:" + "a" * 64,
                }
            ],
        },
        separators=(",", ":"),
    ).encode("ascii")


def test_quota_collector_reloads_evidence_for_every_plan(tmp_path: Path) -> None:
    """N1 break: a daemon restart must not be required for fresher quota evidence."""

    state_root = tmp_path / "quota-state"
    collector = CredentialQuotaCollector(state_root, _quota_evidence_payload(3))

    assert collector.collect("google-one", expected_generation=4).remaining == 3
    collector.sync(
        "google-one",
        remaining=9,
        observed_at="2026-08-29T20:01:00Z",
        source="cloudresourcemanager",
        inventory_fingerprint="sha256:" + "a" * 64,
        expected_generation=4,
        idempotency_key="quota-sync-one",
    )
    assert collector.collect("google-one", expected_generation=4).remaining == 9
    restarted = CredentialQuotaCollector(state_root, _quota_evidence_payload(3))
    assert restarted.collect("google-one", expected_generation=4).remaining == 9


def test_product_service_allows_oauth_client_import_for_new_google_account(
    service: MasterjetControlService,
) -> None:
    """C1 break: an account must be able to import its client before first OAuth."""

    principal = AdminPrincipalV1(
        "local-operator",
        ("fleet.read", "fleet.google.oauth"),
        "unix-peer",
        True,
    )
    service.handle(
        principal,
        AdminRequestV1(
            "google.accounts.add",
            {"account_ref": "google-one", "label": "Quiet Aurora"},
            1,
            "add-google-one",
            None,
        ),
    )
    accounts = service.handle(
        principal,
        AdminRequestV1("google.accounts.list", {}, None, None, None),
    )["accounts"]
    generation = accounts[0]["inventory_generation"]

    plan = service.handle(
        principal,
        AdminRequestV1(
            "google.oauth-client-import.plan",
            {"account_ref": "google-one"},
            generation,
            "client-plan-one",
            None,
        ),
    )

    assert plan["account_ref"] == "google-one"
    assert plan["expected_generation"] == generation
    assert plan["plan_digest"].startswith("sha256:")


def test_first_oauth_token_binds_new_google_account_subject(
    service: MasterjetControlService,
) -> None:
    """C1 break: first account-bound OAuth must establish durable subject authority."""

    principal = AdminPrincipalV1(
        "local-operator",
        ("fleet.read", "fleet.google.oauth"),
        "unix-peer",
        True,
    )
    service.handle(
        principal,
        AdminRequestV1(
            "google.accounts.add",
            {"account_ref": "google-one", "label": "Quiet Aurora"},
            1,
            "add-google-one",
            None,
        ),
    )
    refresh_token = bytearray(b"private-refresh-token")
    writer = service._google_oauth._token_writer

    receipt = writer.store_refresh_token(
        "oauth-token-effect-one",
        account_ref="google-one",
        subject_id="subject-one",
        oauth_client_fingerprint="sha256:" + "b" * 64,
        scope_profile=GoogleOAuthProfileIdV1.INVENTORY_READONLY,
        scope_fingerprint="sha256:" + "c" * 64,
        refresh_token=refresh_token,
    )
    loaded = writer.load_refresh_token(
        "google-one",
        subject_id="subject-one",
        oauth_client_fingerprint="sha256:" + "b" * 64,
        scope_profile=GoogleOAuthProfileIdV1.INVENTORY_READONLY,
    )
    provisioner_refresh_token = bytearray(b"private-provisioner-refresh")
    writer.store_refresh_token(
        "oauth-token-effect-two",
        account_ref="google-one",
        subject_id="subject-one",
        oauth_client_fingerprint="sha256:" + "b" * 64,
        scope_profile=GoogleOAuthProfileIdV1.PROVISIONER,
        scope_fingerprint="sha256:" + "d" * 64,
        refresh_token=provisioner_refresh_token,
    )
    loaded_provisioner = writer.load_refresh_token(
        "google-one",
        subject_id="subject-one",
        oauth_client_fingerprint="sha256:" + "b" * 64,
        scope_profile=GoogleOAuthProfileIdV1.PROVISIONER,
    )

    accounts = service.handle(
        principal,
        AdminRequestV1("google.accounts.list", {}, None, None, None),
    )["accounts"]
    assert receipt.subject_id == "subject-one"
    assert refresh_token == bytearray(len(refresh_token))
    assert loaded == bytearray(b"private-refresh-token")
    assert provisioner_refresh_token == bytearray(len(provisioner_refresh_token))
    assert loaded_provisioner == bytearray(b"private-provisioner-refresh")
    assert accounts[0]["subject_bound"] is True
    loaded[:] = b"\0" * len(loaded)
    loaded_provisioner[:] = b"\0" * len(loaded_provisioner)


@pytest.mark.parametrize(
    ("subject_id", "oauth_client_fingerprint"),
    [
        ("subject-two", "sha256:" + "b" * 64),
        ("subject-one", "sha256:" + "e" * 64),
    ],
)
def test_refresh_token_operation_rejects_changed_effect_binding(
    service: MasterjetControlService,
    subject_id: str,
    oauth_client_fingerprint: str,
) -> None:
    principal = AdminPrincipalV1(
        "local-operator", ("fleet.read", "fleet.google.oauth"), "unix-peer", True
    )
    service.handle(
        principal,
        AdminRequestV1(
            "google.accounts.add",
            {"account_ref": "google-one", "label": "Quiet Aurora"},
            1,
            "add-google-one",
            None,
        ),
    )
    writer = service._google_oauth._token_writer
    writer.store_refresh_token(
        "oauth-token-effect-one",
        account_ref="google-one",
        subject_id="subject-one",
        oauth_client_fingerprint="sha256:" + "b" * 64,
        scope_profile=GoogleOAuthProfileIdV1.PROVISIONER,
        scope_fingerprint="sha256:" + "d" * 64,
        refresh_token=bytearray(b"private-provisioner-refresh"),
    )
    replay_token = bytearray(b"different-private-refresh")

    with pytest.raises(GoogleOAuthSessionError, match="oauth.operation_conflict"):
        writer.store_refresh_token(
            "oauth-token-effect-one",
            account_ref="google-one",
            subject_id=subject_id,
            oauth_client_fingerprint=oauth_client_fingerprint,
            scope_profile=GoogleOAuthProfileIdV1.PROVISIONER,
            scope_fingerprint="sha256:" + "d" * 64,
            refresh_token=replay_token,
        )

    assert replay_token == bytearray(len(replay_token))


def test_refresh_token_vault_effect_reconciles_before_subject_binding(
    service: MasterjetControlService, monkeypatch: pytest.MonkeyPatch
) -> None:
    principal = AdminPrincipalV1(
        "local-operator", ("fleet.read", "fleet.google.oauth"), "unix-peer", True
    )
    service.handle(
        principal,
        AdminRequestV1(
            "google.accounts.add",
            {"account_ref": "google-one", "label": "Quiet Aurora"},
            1,
            "add-google-one",
            None,
        ),
    )
    writer = service._google_oauth._token_writer
    vault_type = type(writer._vault)
    real_store = vault_type.store_projection

    def crash_after_vault(vault, *args, **kwargs):
        real_store(vault, *args, **kwargs)
        raise RuntimeError("simulated_crash")

    monkeypatch.setattr(vault_type, "store_projection", crash_after_vault)
    with pytest.raises(RuntimeError, match="simulated_crash"):
        writer.store_refresh_token(
            "oauth-token-effect-crash",
            account_ref="google-one",
            subject_id="subject-one",
            oauth_client_fingerprint="sha256:" + "b" * 64,
            scope_profile=GoogleOAuthProfileIdV1.PROVISIONER,
            scope_fingerprint="sha256:" + "d" * 64,
            refresh_token=bytearray(b"private-provisioner-refresh"),
        )
    before_reconcile = service.handle(
        principal,
        AdminRequestV1("google.accounts.list", {}, None, None, None),
    )["accounts"]
    assert before_reconcile[0]["subject_bound"] is False

    recovered = writer.lookup_refresh_token_receipt(
        "oauth-token-effect-crash",
        account_ref="google-one",
        scope_profile=GoogleOAuthProfileIdV1.PROVISIONER,
        scope_fingerprint="sha256:" + "d" * 64,
    )
    accounts = service.handle(
        principal,
        AdminRequestV1("google.accounts.list", {}, None, None, None),
    )["accounts"]

    assert recovered is not None
    assert recovered.subject_id == "subject-one"
    assert accounts[0]["subject_bound"] is True


def test_google_access_token_is_refreshed_one_shot_and_account_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    refresh_token = bytearray(b"private-refresh-token")
    calls: list[tuple[str, bytes]] = []

    class OAuth:
        def active_oauth_client_material(self, account_ref, *, expected_generation):
            assert (account_ref, expected_generation) == ("google-one", 4)
            return GoogleOAuthClientMaterialV1(
                "client-id.apps.googleusercontent.com",
                "private-client-secret",
                "https://oauth2.googleapis.com/token",
                "sha256:" + "a" * 64,
            )

    class Tokens:
        def load_refresh_token(
            self,
            account_ref,
            *,
            subject_id,
            oauth_client_fingerprint,
            scope_profile,
        ):
            assert (
                account_ref,
                subject_id,
                oauth_client_fingerprint,
                scope_profile,
            ) == (
                "google-one",
                "subject-one",
                "sha256:" + "a" * 64,
                GoogleOAuthProfileIdV1.PROVISIONER,
            )
            return refresh_token

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def geturl(self):
            return "https://oauth2.googleapis.com/token"

        def read(self, limit):
            assert limit == 64 * 1024 + 1
            return b'{"access_token":"private-access-token","token_type":"Bearer"}'

    def urlopen(request, timeout):
        assert timeout == 10
        calls.append((request.full_url, request.data))
        return Response()

    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    monkeypatch.setattr(
        admin_assembly.GoogleCloudApi, "subject_id", lambda _self: "subject-one"
    )

    token = admin_assembly.GoogleAccessTokenAuthority(
        OAuth(), Tokens()
    ).issue_access_token("google-one", "subject-one", expected_generation=4)

    assert token == "private-access-token"
    assert refresh_token == bytearray(len(refresh_token))
    assert calls[0][0] == "https://oauth2.googleapis.com/token"
    assert b"grant_type=refresh_token" in calls[0][1]
    assert b"private-refresh-token" in calls[0][1]


def test_product_provisioner_uses_vaulted_access_token_authority(
    service: MasterjetControlService,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    principal = AdminPrincipalV1(
        "local-operator", ("fleet.read", "fleet.google.oauth"), "unix-peer", True
    )
    service.handle(
        principal,
        AdminRequestV1(
            "google.accounts.add",
            {"account_ref": "google-one", "label": "Quiet Aurora"},
            1,
            "add-google-one",
            None,
        ),
    )
    writer = service._google_oauth._token_writer
    writer.store_refresh_token(
        "oauth-token-effect-one",
        account_ref="google-one",
        subject_id="subject-one",
        oauth_client_fingerprint="sha256:" + "b" * 64,
        scope_profile=GoogleOAuthProfileIdV1.INVENTORY_READONLY,
        scope_fingerprint="sha256:" + "c" * 64,
        refresh_token=bytearray(b"private-refresh-token"),
    )
    snapshot = service._google_manager._snapshot_for_internal_use()
    calls = []

    class AccessTokens:
        def issue_access_token(self, account_ref, subject_id, *, expected_generation):
            calls.append((account_ref, subject_id, expected_generation))
            return "private-access-token"

    service._google_provisioner._access_tokens = AccessTokens()
    monkeypatch.setattr(
        admin_assembly.GoogleCloudApi, "search_projects", lambda _self: []
    )
    monkeypatch.setattr(
        admin_assembly.GoogleCloudApi, "subject_id", lambda _self: "subject-one"
    )
    observed_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    evidence = admin_assembly.GoogleQuotaEvidenceV1(
        0,
        observed_at,
        "cloudresourcemanager",
        "google-one",
        snapshot.generation,
        snapshot.content_fingerprint,
    )

    plan = service._google_provisioner.plan(
        "google-one",
        expected_generation=snapshot.generation,
        idempotency_key="provision-plan-one",
        quota_evidence=evidence,
    )

    assert plan.quota_remaining == 0
    assert calls == [("google-one", "subject-one", snapshot.generation)]

    restarted = admin_assembly.GoogleProvisioner(
        tmp_path / "state" / "google-provisioner",
        service._google_manager,
        service._google_provisioner._store,
        AccessTokens(),
    )
    replayed = restarted.plan(
        "google-one",
        expected_generation=snapshot.generation,
        idempotency_key="provision-plan-one",
        quota_evidence=evidence,
    )
    with pytest.raises(
        admin_assembly.GoogleCloudProvisionerError,
        match="provisioner.confirmation_invalid",
    ):
        restarted.apply(
            "google-one",
            expected_generation=snapshot.generation,
            idempotency_key="provision-apply-one",
            plan_digest="sha256:" + "f" * 64,
        )
    receipt = restarted.apply(
        "google-one",
        expected_generation=snapshot.generation,
        idempotency_key="provision-apply-one",
        plan_digest=plan.fingerprint,
    )
    replayed_receipt = admin_assembly.GoogleProvisioner(
        tmp_path / "state" / "google-provisioner",
        service._google_manager,
        service._google_provisioner._store,
        AccessTokens(),
    ).apply(
        "google-one",
        expected_generation=snapshot.generation,
        idempotency_key="provision-apply-one",
        plan_digest=plan.fingerprint,
    )

    assert replayed == plan
    assert receipt == admin_assembly.ProvisionReceipt(0, 0)
    assert replayed_receipt == receipt
    assert calls == [
        ("google-one", "subject-one", snapshot.generation),
        ("google-one", "subject-one", snapshot.generation),
    ]
    with restarted._state.locked():
        document = restarted._read_locked()
        document["plans"][0]["plan"]["quota_remaining"] = True
        restarted._state.replace_json_locked(
            admin_assembly._PROVISIONER_DOCUMENT, document
        )
    with pytest.raises(
        admin_assembly.HiveStateError, match="invalid_google_provisioner_plans"
    ):
        admin_assembly.GoogleProvisioner(
            tmp_path / "state" / "google-provisioner",
            service._google_manager,
            service._google_provisioner._store,
            AccessTokens(),
        )


def test_product_provisioner_singleflights_same_apply_key(
    service: MasterjetControlService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    principal = AdminPrincipalV1(
        "local-operator", ("fleet.read", "fleet.google.oauth"), "unix-peer", True
    )
    service.handle(
        principal,
        AdminRequestV1(
            "google.accounts.add",
            {"account_ref": "google-one", "label": "Quiet Aurora"},
            1,
            "add-google-one",
            None,
        ),
    )
    service._google_oauth._token_writer.store_refresh_token(
        "oauth-token-effect-one",
        account_ref="google-one",
        subject_id="subject-one",
        oauth_client_fingerprint="sha256:" + "b" * 64,
        scope_profile=GoogleOAuthProfileIdV1.PROVISIONER,
        scope_fingerprint="sha256:" + "c" * 64,
        refresh_token=bytearray(b"private-refresh-token"),
    )
    snapshot = service._google_manager._snapshot_for_internal_use()
    service._google_provisioner._access_tokens = type(
        "AccessTokens",
        (),
        {"issue_access_token": lambda _self, *_args, **_kwargs: "private-access-token"},
    )()
    monkeypatch.setattr(
        admin_assembly.GoogleCloudApi, "search_projects", lambda _self: []
    )
    plan = service._google_provisioner.plan(
        "google-one",
        expected_generation=snapshot.generation,
        idempotency_key="provision-plan-one",
        quota_evidence=admin_assembly.GoogleQuotaEvidenceV1(
            1,
            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "cloudresourcemanager",
            "google-one",
            snapshot.generation,
            snapshot.content_fingerprint,
        ),
    )
    created = 0
    create_lock = threading.Lock()
    both_inside_create = threading.Event()
    release_create = threading.Event()

    class Api:
        def subject_id(self):
            return "subject-one"

        def create_project(self, project_id, _project_name):
            nonlocal created
            with create_lock:
                created += 1
                if created == 2:
                    both_inside_create.set()
            release_create.wait(2)
            return {"projectId": project_id, "name": "projects/200001"}

        def enable_required_services(self, _project_number):
            return {}

        def list_keys(self, _project_number):
            return []

        def create_restricted_key(self, project_number, display_name):
            return {
                "name": f"projects/{project_number}/locations/global/keys/key-one",
                "uid": "uid-one",
                "keyString": "private-key-one",
                "displayName": display_name,
            }

    api = Api()
    monkeypatch.setattr(service._google_provisioner, "_api", lambda *_args: api)

    def apply():
        return service._google_provisioner.apply(
            "google-one",
            expected_generation=snapshot.generation,
            idempotency_key="provision-apply-one",
            plan_digest=plan.fingerprint,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(apply) for _ in range(2)]
        both_inside_create.wait(0.5)
        release_create.set()
        receipts = [future.result(timeout=3) for future in futures]

    assert created == 1
    assert receipts == [admin_assembly.ProvisionReceipt(1, 1)] * 2


def test_product_billing_uses_vaulted_access_token_authority(
    service: MasterjetControlService,
) -> None:
    principal = AdminPrincipalV1(
        "local-operator", ("fleet.read", "fleet.google.oauth"), "unix-peer", True
    )
    service.handle(
        principal,
        AdminRequestV1(
            "google.accounts.add",
            {"account_ref": "google-one", "label": "Quiet Aurora"},
            1,
            "add-google-one",
            None,
        ),
    )
    service._google_oauth._token_writer.store_refresh_token(
        "oauth-token-effect-one",
        account_ref="google-one",
        subject_id="subject-one",
        oauth_client_fingerprint="sha256:" + "b" * 64,
        scope_profile=GoogleOAuthProfileIdV1.INVENTORY_READONLY,
        scope_fingerprint="sha256:" + "c" * 64,
        refresh_token=bytearray(b"private-refresh-token"),
    )
    snapshot = service._google_manager._snapshot_for_internal_use()
    calls = []

    class AccessTokens:
        def issue_access_token(self, account_ref, subject_id, *, expected_generation):
            calls.append((account_ref, subject_id, expected_generation))
            return "private-access-token"

    authority = service._google_billing._authority
    authority._access_tokens = AccessTokens()

    lease = authority.lease_billing_effect("google-one", "subject-one")

    assert (lease.account_ref, lease.subject_id) == ("google-one", "subject-one")
    assert calls == [("google-one", "subject-one", snapshot.generation)]


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _product_directories(tmp_path: Path) -> tuple[Path, Path, Path, int]:
    credentials = tmp_path / "credentials"
    runtime = tmp_path / "runtime"
    state = tmp_path / "state"
    credentials.mkdir(mode=0o700)
    runtime.mkdir(mode=0o700)
    state.mkdir(mode=0o700)
    port = _free_port()
    scopes = ["fleet.read", "fleet.openai.write", "fleet.host.read"]
    config = {
        "schema_version": 1,
        "http_host": "127.0.0.1",
        "http_port": port,
        "origin_host": "admin.internal",
        "authority_mode": "bearer",
        "local_subject": "local-operator",
        "local_scopes": scopes,
        "remote_subject": "remote-operator",
        "remote_scopes": scopes,
        "trusted_proxy_addresses": ["127.0.0.1"],
    }
    _credential(
        credentials / "admin-config",
        json.dumps(config, separators=(",", ":")).encode("ascii"),
    )
    _credential(credentials / "admin-bearer", b"round-one-bearer")
    _credential(
        credentials / "admin-totp",
        base64.b32encode(b"12345678901234567890"),
    )
    _credential(credentials / "admin-attestation", b"a" * 32)
    _credential(credentials / "admin-vault-key", b"v" * 32)
    _credential(
        credentials / "admin-quota-evidence",
        b'{"schema_version":1,"accounts":[]}',
    )
    return credentials, runtime, state, port


@pytest.fixture(scope="module")
def installed_admin_entrypoint(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Install the exact console script without consulting package indexes."""

    install_root = tmp_path_factory.mktemp("installed-admin")
    environment = {
        key: value for key, value in os.environ.items() if key != "PYTHONPATH"
    }
    environment["PIP_CACHE_DIR"] = os.fspath(install_root / "pip-cache")
    venv.EnvBuilder(with_pip=True, system_site_packages=True).create(install_root)
    interpreter = install_root / "bin" / "python"
    repository = Path(__file__).resolve().parents[1]
    source = install_root / "source"
    source.mkdir(mode=0o700)
    shutil.copy2(repository / "pyproject.toml", source / "pyproject.toml")
    shutil.copytree(repository / "src", source / "src")
    installed = subprocess.run(
        [
            os.fspath(interpreter),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-deps",
            "--no-build-isolation",
            "--no-cache-dir",
            os.fspath(source),
        ],
        cwd=install_root,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        check=False,
    )
    assert installed.returncode == 0
    entrypoint = install_root / "bin" / "codex-master-admin"
    assert entrypoint.is_file()
    assert os.access(entrypoint, os.X_OK)
    return entrypoint


@pytest.fixture
def service(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[MasterjetControlService]:
    """Use the exact production owner graph in lifecycle tests, never placeholders."""

    credentials, runtime, state, _port = _product_directories(tmp_path)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", os.fspath(credentials))
    monkeypatch.setenv("RUNTIME_DIRECTORY", os.fspath(runtime))
    monkeypatch.setenv("STATE_DIRECTORY", os.fspath(state))
    owner_runtime = assemble_admin_runtime()
    try:
        yield owner_runtime.service
    finally:
        owner_runtime.close()


def test_installed_product_path_uses_credentials_both_adapters_and_sigterm(
    tmp_path: Path,
    installed_admin_entrypoint: Path,
) -> None:
    """C1/I5 break: green wrappers cannot replace a running installed daemon."""

    credentials, runtime, state, port = _product_directories(tmp_path)
    notify_path = tmp_path / "notify.sock"
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notify:
        notify.bind(os.fspath(notify_path))
        notify.settimeout(4)
        environment = {
            key: value for key, value in os.environ.items() if key != "PYTHONPATH"
        } | {
            "CREDENTIALS_DIRECTORY": os.fspath(credentials),
            "RUNTIME_DIRECTORY": os.fspath(runtime),
            "STATE_DIRECTORY": os.fspath(state),
            "NOTIFY_SOCKET": os.fspath(notify_path),
        }
        process = subprocess.Popen(
            [os.fspath(installed_admin_entrypoint)],
            cwd=tmp_path,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            assert notify.recv(128) == b"READY=1"
            socket_path = runtime / "admin.sock"
            attestation_fd = os.open(
                credentials / "admin-attestation",
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            try:
                from codex_master.admin_contracts import AdminRequestV1
                from codex_master.admin_socket import AdminSocketClient

                client = AdminSocketClient(
                    socket_path,
                    expected_server_uid=os.geteuid(),
                    attestation_key_fd=attestation_fd,
                )
                added = client.call(
                    AdminRequestV1(
                        "openai.accounts.add",
                        {"account_ref": "openai-one", "label": "OpenAI One"},
                        1,
                        "round-one-add",
                        None,
                    )
                )
            finally:
                os.close(attestation_fd)
            assert added["account"]["ref"] == "openai-one"  # type: ignore[index]

            body = json.dumps(
                {
                    "schema_version": 1,
                    "operation": "openai.accounts.list",
                    "arguments": {},
                },
                separators=(",", ":"),
            ).encode("ascii")
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
            connection.request(
                "POST",
                "/admin/v1",
                body=body,
                headers={
                    "Authorization": "Bearer round-one-bearer",
                    "Host": "admin.internal",
                    "X-Forwarded-Host": "admin.internal",
                    "X-Forwarded-Proto": "https",
                    "Content-Type": "application/json",
                },
            )
            response = connection.getresponse()
            payload = json.loads(response.read())
            connection.close()
            assert response.status == 200
            assert payload["accounts"] == [{"ref": "openai-one", "generation": 1}]

            endpoint = socket_path.lstat()
            assert endpoint.st_uid == os.geteuid()
            assert endpoint.st_mode & 0o777 == 0o600
            process.send_signal(signal.SIGTERM)
            assert notify.recv(128) == b"STOPPING=1"
            assert process.wait(timeout=3) == 0
            assert not socket_path.exists()
            for item in state.rglob("*"):
                metadata = item.lstat()
                assert metadata.st_uid == os.geteuid()
                assert metadata.st_mode & 0o007 == 0
        finally:
            if process.poll() is None:
                process.kill()
            stdout, stderr = process.communicate(timeout=2)
    combined = stdout + stderr
    assert b"round-one-bearer" not in combined
    assert b"12345678901234567890" not in combined
    assert combined == b""


def test_blocked_real_effect_subprocess_exits_by_deadline_and_unlinks_socket(
    tmp_path: Path,
) -> None:
    """I3/I5 break: a wedged real request must not strand the owned socket."""

    credentials, runtime, state, _port = _product_directories(tmp_path)
    notify_path = tmp_path / "blocked-notify.sock"
    child = """
import threading
from codex_master.admin_assembly import assemble_admin_runtime

runtime = assemble_admin_runtime()
registry = runtime.service._account_registry
def block(*_args, **_kwargs):
    threading.Event().wait()
registry.add_account = block
raise SystemExit(runtime.run())
"""
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notify:
        notify.bind(os.fspath(notify_path))
        notify.settimeout(8)
        environment = {
            **os.environ,
            "PYTHONPATH": os.fspath(Path(__file__).resolve().parents[1] / "src"),
            "CREDENTIALS_DIRECTORY": os.fspath(credentials),
            "RUNTIME_DIRECTORY": os.fspath(runtime),
            "STATE_DIRECTORY": os.fspath(state),
            "NOTIFY_SOCKET": os.fspath(notify_path),
        }
        process = subprocess.Popen(
            [sys.executable, "-c", child],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        socket_path = runtime / "admin.sock"
        try:
            assert notify.recv(128) == b"READY=1"
            attestation_fd = os.open(
                credentials / "admin-attestation",
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            try:
                from codex_master.admin_contracts import AdminRequestV1
                from codex_master.admin_socket import (
                    AdminSocketClient,
                    AdminSocketError,
                )

                client = AdminSocketClient(
                    socket_path,
                    timeout_seconds=1,
                    attestation_key_fd=attestation_fd,
                )
                with pytest.raises(AdminSocketError):
                    client.call(
                        AdminRequestV1(
                            "openai.accounts.add",
                            {"account_ref": "blocked-one", "label": "Blocked One"},
                            1,
                            "blocked-add",
                            None,
                        )
                    )
            finally:
                os.close(attestation_fd)
            before = time.monotonic()
            process.send_signal(signal.SIGTERM)
            assert notify.recv(128) == b"STOPPING=1"
            assert process.wait(timeout=7) == 1
            assert time.monotonic() - before < 7
            assert not socket_path.exists()
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=2)
        stdout, stderr = process.communicate(timeout=1)
        assert stdout == b""
        assert stderr == b""
