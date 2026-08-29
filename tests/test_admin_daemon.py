from __future__ import annotations

import base64
import http.client
import os
from pathlib import Path
import signal
import threading

from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
import pytest

from codex_master.admin_auth import MasterjetBearerVerifier, TotpStepUpVerifier
from codex_master.admin_daemon import (
    AdminDaemon,
    AdminDaemonShutdownError,
    AdminDaemonStartupError,
    CloudflareJwksFetchError,
    CloudflareJwksFetcher,
    JwksRefreshShutdownError,
    RefreshingCloudflareAccessVerifier,
    main,
)
from codex_master.admin_http import AdminHttpServer
from codex_master.admin_service import MasterjetControlService


ISSUER = "https://team.cloudflareaccess.com"
AUDIENCE = "application-audience"
NOW = 2_000_000_000


def _service() -> MasterjetControlService:
    owner = object()
    return MasterjetControlService(
        operation_store=owner,  # type: ignore[arg-type]
        openai_accounts=None,
        openai_credentials=None,
        google_manager=owner,  # type: ignore[arg-type]
        google_oauth=None,
        quota_collector=None,
        google_provisioner=None,
        google_billing=None,
        host_registry=owner,  # type: ignore[arg-type]
        secret_ingress=None,
    )


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

    def serve_forever(self, *, poll_interval: float = 0.5) -> None:
        del poll_interval
        self._events.append("http-serving")
        self._stopped.wait()

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


def test_readiness_cannot_race_a_partially_bound_transport() -> None:
    """Production break: systemd may route traffic while only AF_UNIX is bound."""

    service = _service()
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


def test_http_bind_failure_rolls_back_only_the_owned_socket() -> None:
    """Production break: a failed private origin can leave a live local socket."""

    service = _service()
    events: list[str] = []

    def fail_http(_candidate: MasterjetControlService) -> _Http:
        raise OSError("bind unavailable")

    daemon = _daemon(service, events, http_factory=fail_http)

    with pytest.raises(AdminDaemonStartupError, match="control.admin_startup_failed"):
        daemon.start()

    assert events == ["socket-bound", "socket-closed"]
    assert daemon.ready is False


def test_both_adapters_receive_the_one_exact_service_instance() -> None:
    """Production break: separate factories split idempotency and owner state."""

    service = _service()
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


def test_sigterm_stops_admission_then_finishes_all_owned_lifecycles() -> None:
    """Production break: SIGTERM can exit with listeners or authorities still live."""

    service = _service()
    events: list[str] = []
    notifications: list[str] = []
    daemon = _daemon(service, events, notifications=notifications)

    def terminate_when_ready() -> None:
        assert daemon.wait_ready(1)
        os.kill(os.getpid(), signal.SIGTERM)

    sender = threading.Thread(target=terminate_when_ready)
    sender.start()
    assert daemon.run() == 0
    sender.join(1)
    assert not sender.is_alive()
    assert notifications == ["READY=1", "STOPPING=1"]
    assert "http-admission-stopped" in events
    assert "socket-closed" in events
    assert "http-drained" in events
    assert "http-closed" in events
    assert "authorities-closed" in events
    assert "jwks-closed" in events


def test_blocked_socket_shutdown_is_not_reported_as_success() -> None:
    """Production break: an incomplete socket worker was previously easy to mask."""

    service = _service()
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


def _private_fd(tmp_path: Path, name: str, payload: bytes) -> int:
    path = tmp_path / name
    path.write_bytes(payload)
    path.chmod(0o600)
    return os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)


def test_daemon_does_not_publish_an_unauthenticated_health_route(
    tmp_path: Path,
) -> None:
    """Production break: a health shortcut can bypass the HTTP auth boundary."""

    service = _service()
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


def test_cli_fails_closed_until_real_business_owners_can_be_composed(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Production break: dummy owners must never make the daemon look operational."""

    assert main([]) == os.EX_CONFIG
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "codex-master-admin: control.owner_composition_unavailable\n"
    assert "secret" not in captured.err
