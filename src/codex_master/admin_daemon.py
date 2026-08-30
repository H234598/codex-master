"""Owned lifecycle for the private Masterjet administration transports."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
import json
import math
import os
import re
import signal
import socket
import sys
import threading
import time
from types import FrameType
from typing import Any, Final, Protocol, cast
import urllib.error
import urllib.request

import jwt

from .admin_auth import AdminAuthError, CloudflareAccessVerifier
from .admin_service import MasterjetControlService


JWKS_FETCH_TIMEOUT_SECONDS: Final[float] = 5.0
JWKS_MAX_RESPONSE_BYTES: Final[int] = 64 * 1024
JWKS_REFRESH_INTERVAL_SECONDS: Final[float] = 300.0
JWKS_REFRESH_TIMEOUT_SECONDS: Final[float] = 6.0
DAEMON_SHUTDOWN_TIMEOUT_SECONDS: Final[float] = 5.0
_TEAM_DOMAIN = re.compile(
    r"(?=.{1,253}\Z)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"cloudflareaccess\.com\Z",
    re.ASCII,
)
_KID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}\Z", re.ASCII)


class AdminDaemonStartupError(RuntimeError):
    """Stable failure before readiness was published."""

    def __init__(self, failures: Sequence[str] = ()) -> None:
        self.failures = tuple(failures)
        detail = ";".join(self.failures)
        message = "control.admin_startup_failed"
        super().__init__(f"{message};{detail}" if detail else message)


class AdminDaemonShutdownError(RuntimeError):
    """One or more owned workers did not finish cleanly within the bound."""

    def __init__(self, failures: Sequence[str]) -> None:
        self.failures = tuple(failures)
        super().__init__(";".join(self.failures) or "control.admin_shutdown_incomplete")


class CloudflareJwksFetchError(RuntimeError):
    """Code-only failure at the fixed Cloudflare JWKS fetch boundary."""

    def __init__(self) -> None:
        super().__init__("authority.jwks_unavailable")


class JwksRefreshShutdownError(RuntimeError):
    """The periodic refresher or its bounded fetch worker remains live."""

    def __init__(self) -> None:
        super().__init__("authority.jwks_shutdown_incomplete")


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        del request, file_pointer, code, message, headers, new_url
        return None


def _open_without_redirects(request: urllib.request.Request, *, timeout: float) -> Any:
    opener = urllib.request.build_opener(_NoRedirectHandler())
    return opener.open(request, timeout=timeout)


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


class CloudflareJwksFetcher:
    """Fetch only one configured Cloudflare team certs endpoint."""

    def __init__(
        self,
        team_domain: str,
        *,
        open_response: Callable[..., Any] = _open_without_redirects,
    ) -> None:
        if (
            type(team_domain) is not str
            or _TEAM_DOMAIN.fullmatch(team_domain) is None
            or not callable(open_response)
        ):
            raise CloudflareJwksFetchError
        self._url = f"https://{team_domain}/cdn-cgi/access/certs"
        self._open_response = open_response

    @property
    def url(self) -> str:
        return self._url

    def __call__(self) -> Mapping[str, object]:
        request = urllib.request.Request(
            self._url,
            headers={"Accept": "application/json"},
            method="GET",
        )
        try:
            with self._open_response(
                request, timeout=JWKS_FETCH_TIMEOUT_SECONDS
            ) as response:
                if response.status != 200 or response.geturl() != self._url:
                    raise ValueError
                content_type = response.headers.get("Content-Type")
                if (
                    type(content_type) is not str
                    or content_type.split(";", 1)[0].strip().lower()
                    != "application/json"
                ):
                    raise ValueError
                content_length = response.headers.get("Content-Length")
                if content_length is not None and (
                    type(content_length) is not str
                    or not content_length.isascii()
                    or not content_length.isdecimal()
                    or int(content_length) > JWKS_MAX_RESPONSE_BYTES
                ):
                    raise ValueError
                payload = response.read(JWKS_MAX_RESPONSE_BYTES + 1)
            if (
                type(payload) is not bytes
                or not payload
                or len(payload) > JWKS_MAX_RESPONSE_BYTES
            ):
                raise ValueError
            value = json.loads(
                payload.decode("utf-8"),
                object_pairs_hook=_strict_json_object,
                parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
            )
            if type(value) is not dict:
                raise ValueError
            return cast(dict[str, object], value)
        except (KeyboardInterrupt, SystemExit):
            raise
        except BaseException:
            raise CloudflareJwksFetchError from None

    def __repr__(self) -> str:
        return f"CloudflareJwksFetcher(url={self._url!r})"


def _jwks_keys(document: Mapping[str, object]) -> tuple[dict[str, object], ...]:
    raw_keys = document.get("keys") if isinstance(document, Mapping) else None
    if type(raw_keys) is not list:
        raise AdminAuthError("authority.configuration_invalid")
    keys: list[dict[str, object]] = []
    for raw in raw_keys:
        if type(raw) is not dict:
            raise AdminAuthError("authority.configuration_invalid")
        keys.append(dict(cast(dict[str, object], raw)))
    return tuple(keys)


def _merge_keysets(
    current: Sequence[Mapping[str, object]],
    previous: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    merged: list[dict[str, object]] = []
    kids: set[object] = set()
    for raw in (*current, *previous):
        kid = raw.get("kid")
        if kid in kids:
            continue
        kids.add(kid)
        merged.append(dict(raw))
    return {"keys": merged}


class RefreshingCloudflareAccessVerifier:
    """Cloudflare verifier with bounded rotation and two-generation LKG state."""

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        initial_jwks: Mapping[str, object],
        loader: Callable[[], Mapping[str, object]],
        principal_resolver: Callable[[str, Mapping[str, object]], Sequence[str]],
        algorithms: Sequence[str] = ("RS256",),
        clock: Callable[[], float] = time.time,
        max_token_age_seconds: int = 600,
        refresh_interval_seconds: float = JWKS_REFRESH_INTERVAL_SECONDS,
        refresh_timeout_seconds: float = JWKS_REFRESH_TIMEOUT_SECONDS,
        unknown_kid_cooldown_seconds: float = 30.0,
    ) -> None:
        if (
            not callable(loader)
            or not callable(clock)
            or type(refresh_interval_seconds) not in {int, float}
            or not math.isfinite(refresh_interval_seconds)
            or refresh_interval_seconds <= 0
            or type(refresh_timeout_seconds) not in {int, float}
            or not math.isfinite(refresh_timeout_seconds)
            or refresh_timeout_seconds <= 0
            or type(unknown_kid_cooldown_seconds) not in {int, float}
            or not math.isfinite(unknown_kid_cooldown_seconds)
            or unknown_kid_cooldown_seconds <= 0
        ):
            raise AdminAuthError("authority.configuration_invalid")
        current = _jwks_keys(initial_jwks)
        verifier = CloudflareAccessVerifier(
            issuer=issuer,
            audience=audience,
            jwks={"keys": list(current)},
            principal_resolver=principal_resolver,
            algorithms=algorithms,
            clock=clock,
            max_token_age_seconds=max_token_age_seconds,
        )
        self._issuer = issuer
        self._audience = audience
        self._loader = loader
        self._principal_resolver = principal_resolver
        self._algorithms = tuple(algorithms)
        self._clock = clock
        self._max_token_age_seconds = max_token_age_seconds
        self._refresh_interval = float(refresh_interval_seconds)
        self._refresh_timeout = float(refresh_timeout_seconds)
        self._unknown_kid_cooldown = float(unknown_kid_cooldown_seconds)
        self._state_lock = threading.RLock()
        self._refresh_lock = threading.Lock()
        self._stop = threading.Event()
        self._periodic_thread: threading.Thread | None = None
        self._worker: threading.Thread | None = None
        self._worker_value: Mapping[str, object] | None = None
        self._worker_failed = False
        self._verifier = verifier
        self._current = current
        self._previous: tuple[dict[str, object], ...] = ()
        self._refreshed_at: float | None = None
        self._generation = 0
        self._unknown_kid_retry_after = 0.0
        self._closed = False

    def _candidate(
        self,
        current: Sequence[Mapping[str, object]],
        previous: Sequence[Mapping[str, object]],
    ) -> CloudflareAccessVerifier:
        return CloudflareAccessVerifier(
            issuer=self._issuer,
            audience=self._audience,
            jwks=_merge_keysets(current, previous),
            principal_resolver=self._principal_resolver,
            algorithms=self._algorithms,
            clock=self._clock,
            max_token_age_seconds=self._max_token_age_seconds,
        )

    def verify(self, assertion: str):
        kid: object = None
        try:
            header = jwt.get_unverified_header(assertion)
            if type(header) is dict:
                kid = header.get("kid")
        except Exception:
            pass
        with self._state_lock:
            verifier = self._verifier
            known_kids = verifier.jwks_kids
            generation = self._generation
            retry_after = self._unknown_kid_retry_after
        if (
            type(kid) is str
            and _KID.fullmatch(kid) is not None
            and kid not in known_kids
            and time.monotonic() >= retry_after
        ):
            self._refresh_unknown_kid(generation)
            with self._state_lock:
                verifier = self._verifier
        return verifier.verify(assertion)

    def _refresh_unknown_kid(self, observed_generation: int) -> None:
        deadline = time.monotonic() + self._refresh_timeout
        if not self._refresh_lock.acquire(timeout=self._refresh_timeout):
            return
        try:
            with self._state_lock:
                now = time.monotonic()
                if (
                    self._closed
                    or self._generation != observed_generation
                    or now < self._unknown_kid_retry_after
                ):
                    return
            self._refresh_locked(deadline)
            with self._state_lock:
                self._unknown_kid_retry_after = (
                    time.monotonic() + self._unknown_kid_cooldown
                )
        finally:
            self._refresh_lock.release()

    def _load(self) -> None:
        value: Mapping[str, object] | None = None
        failed = False
        try:
            value = self._loader()
        except BaseException:
            failed = True
        with self._state_lock:
            self._worker_value = value
            self._worker_failed = failed

    def _load_bounded(self, timeout_seconds: float) -> Mapping[str, object] | None:
        with self._state_lock:
            worker = self._worker
            if worker is None:
                self._worker_value = None
                self._worker_failed = False
                worker = threading.Thread(
                    target=self._load,
                    name="masterjet-admin-jwks-fetch",
                    daemon=True,
                )
                self._worker = worker
                worker.start()
        worker.join(timeout_seconds)
        if worker.is_alive():
            return None
        with self._state_lock:
            if self._worker is not worker:
                return None
            value = self._worker_value
            failed = self._worker_failed
            self._worker = None
            self._worker_value = None
            self._worker_failed = False
        return None if failed else value

    def refresh(self) -> bool:
        deadline = time.monotonic() + self._refresh_timeout
        if not self._refresh_lock.acquire(timeout=self._refresh_timeout):
            return False
        try:
            return self._refresh_locked(deadline)
        finally:
            self._refresh_lock.release()

    def _refresh_locked(self, deadline: float) -> bool:
        try:
            with self._state_lock:
                if self._closed:
                    return False
            replacement = self._load_bounded(max(0.0, deadline - time.monotonic()))
            if replacement is None:
                return False
            replacement_keys = _jwks_keys(replacement)
            self._candidate(replacement_keys, ())
            with self._state_lock:
                previous = self._current
            candidate = self._candidate(replacement_keys, previous)
            refreshed_at = self._clock()
            if (
                type(refreshed_at) not in {int, float}
                or not math.isfinite(refreshed_at)
                or refreshed_at < 0
            ):
                return False
            with self._state_lock:
                if self._closed:
                    return False
                self._verifier = candidate
                self._previous = previous
                self._current = replacement_keys
                self._refreshed_at = float(refreshed_at)
                self._generation += 1
            return True
        except Exception:
            return False

    def _periodic(self) -> None:
        while not self._stop.wait(self._refresh_interval):
            self.refresh()

    def start(self) -> None:
        with self._state_lock:
            if self._closed or self._periodic_thread is not None:
                raise AdminAuthError("authority.configuration_invalid")
            thread = threading.Thread(
                target=self._periodic,
                name="masterjet-admin-jwks-refresh",
                daemon=True,
            )
            self._periodic_thread = thread
            thread.start()

    def close(self, timeout_seconds: float) -> None:
        if (
            type(timeout_seconds) not in {int, float}
            or not math.isfinite(timeout_seconds)
            or timeout_seconds < 0
        ):
            raise JwksRefreshShutdownError
        deadline = time.monotonic() + float(timeout_seconds)
        with self._state_lock:
            self._closed = True
            periodic = self._periodic_thread
            worker = self._worker
            self._stop.set()
        if periodic is not None:
            periodic.join(max(0.0, deadline - time.monotonic()))
        if worker is not None:
            worker.join(max(0.0, deadline - time.monotonic()))
        if (periodic is not None and periodic.is_alive()) or (
            worker is not None and worker.is_alive()
        ):
            raise JwksRefreshShutdownError
        with self._state_lock:
            if self._periodic_thread is periodic:
                self._periodic_thread = None
            if self._worker is worker:
                self._worker = None
                self._worker_value = None
                self._worker_failed = False

    def jwks_state(self) -> dict[str, object]:
        """Return only freshness and key identifiers, never key material."""

        with self._state_lock:
            return {
                "current_kids": tuple(cast(str, key["kid"]) for key in self._current),
                "previous_kids": tuple(cast(str, key["kid"]) for key in self._previous),
                "refreshed_at": self._refreshed_at,
            }

    def __repr__(self) -> str:
        return "RefreshingCloudflareAccessVerifier(<redacted>)"


class _SocketAdapter(Protocol):
    def start(self) -> None: ...

    def close(self) -> None: ...


class _HttpAdapter(Protocol):
    service: MasterjetControlService

    def serve_forever(self, *, poll_interval: float = 0.5) -> None: ...

    def wait_serving(self, timeout_seconds: float) -> bool: ...

    def shutdown(self) -> None: ...

    def drain(self, timeout_seconds: float) -> None: ...

    def server_close(self) -> None: ...

    def close_authorities(self) -> None: ...


class _JwksRefresher(Protocol):
    def start(self) -> None: ...

    def close(self, timeout_seconds: float) -> None: ...


def _failure_code(error: BaseException) -> str:
    value = str(error)
    return value if value and len(value) <= 256 else "control.admin_shutdown_incomplete"


class AdminDaemon:
    """Own exactly one control service and the two transports that share it."""

    def __init__(
        self,
        service: MasterjetControlService,
        *,
        socket_factory: Callable[[MasterjetControlService], _SocketAdapter],
        http_factory: Callable[[MasterjetControlService], _HttpAdapter],
        jwks_refresher: _JwksRefresher | None = None,
        notifier: Callable[[str], None] | None = None,
        shutdown_timeout_seconds: float = DAEMON_SHUTDOWN_TIMEOUT_SECONDS,
    ) -> None:
        if (
            type(service) is not MasterjetControlService
            or not callable(socket_factory)
            or not callable(http_factory)
            or (notifier is not None and not callable(notifier))
            or type(shutdown_timeout_seconds) not in {int, float}
            or not math.isfinite(shutdown_timeout_seconds)
            or shutdown_timeout_seconds <= 0
        ):
            raise ValueError("control.admin_configuration_invalid")
        self._service = service
        self._socket_factory = socket_factory
        self._http_factory = http_factory
        self._jwks_refresher = jwks_refresher
        self._notifier = notifier or _systemd_notify
        self._shutdown_timeout = float(shutdown_timeout_seconds)
        self._state_lock = threading.RLock()
        self._notification_lock = threading.Lock()
        self._ready = threading.Event()
        self._stop_requested = threading.Event()
        self._socket: _SocketAdapter | None = None
        self._http: _HttpAdapter | None = None
        self._http_thread: threading.Thread | None = None
        self._http_failure: BaseException | None = None
        self._started = False
        self._ready_published = False
        self._stopping = False
        self._incomplete_resources: tuple[str, ...] = ()

    @property
    def ready(self) -> bool:
        return self._ready.is_set()

    @property
    def incomplete_resources(self) -> tuple[str, ...]:
        with self._state_lock:
            return self._incomplete_resources

    def wait_ready(self, timeout_seconds: float) -> bool:
        return self._ready.wait(timeout_seconds)

    def request_stop(self) -> None:
        self._stop_requested.set()

    def _serve_http(self, http: _HttpAdapter) -> None:
        try:
            http.serve_forever(poll_interval=0.1)
        except BaseException as error:
            with self._state_lock:
                self._http_failure = error
            self.request_stop()
            self._revoke_readiness()

    def _revoke_readiness(self) -> None:
        with self._notification_lock:
            with self._state_lock:
                published = self._ready_published
                self._ready_published = False
                self._ready.clear()
            if published:
                try:
                    self._notifier("STOPPING=1")
                except Exception:
                    pass

    def _validate_socket(self, adapter: _SocketAdapter) -> None:
        bound_service = getattr(adapter, "service", getattr(adapter, "_service", None))
        if bound_service is not self._service:
            raise ValueError

    def _validate_http(self, adapter: _HttpAdapter) -> None:
        if getattr(adapter, "service", None) is not self._service:
            raise ValueError

    def start(self) -> None:
        with self._state_lock:
            if self._started or self._stopping or self._incomplete_resources:
                raise AdminDaemonStartupError
        socket_adapter: _SocketAdapter | None = None
        http_adapter: _HttpAdapter | None = None
        http_thread: threading.Thread | None = None
        refresher_started = False
        try:
            socket_adapter = self._socket_factory(self._service)
            self._validate_socket(socket_adapter)
            socket_adapter.start()
            http_adapter = self._http_factory(self._service)
            self._validate_http(http_adapter)
            http_thread = threading.Thread(
                target=self._serve_http,
                args=(http_adapter,),
                name="masterjet-admin-http",
                daemon=True,
            )
            with self._state_lock:
                self._socket = socket_adapter
                self._http = http_adapter
                self._http_thread = http_thread
            http_thread.start()
            if not http_adapter.wait_serving(self._shutdown_timeout):
                raise RuntimeError("control.http_serve_failed")
            with self._state_lock:
                if self._http_failure is not None or not http_thread.is_alive():
                    raise RuntimeError("control.http_serve_failed")
            if self._jwks_refresher is not None:
                self._jwks_refresher.start()
                refresher_started = True
            with self._state_lock:
                if self._http_failure is not None or not http_thread.is_alive():
                    raise RuntimeError("control.http_serve_failed")
            with self._notification_lock:
                with self._state_lock:
                    if self._http_failure is not None or not http_thread.is_alive():
                        raise RuntimeError("control.http_serve_failed")
                    self._ready_published = True
                self._notifier("READY=1")
            with self._state_lock:
                if self._http_failure is not None or not http_thread.is_alive():
                    raise RuntimeError("control.http_serve_failed")
                self._started = True
                self._ready.set()
        except BaseException:
            self._revoke_readiness()
            failures = self._rollback_startup(
                socket_adapter,
                http_adapter,
                http_thread,
                refresher_started=refresher_started,
            )
            raise AdminDaemonStartupError(failures) from None

    def _rollback_startup(
        self,
        socket_adapter: _SocketAdapter | None,
        http_adapter: _HttpAdapter | None,
        http_thread: threading.Thread | None,
        *,
        refresher_started: bool,
    ) -> tuple[str, ...]:
        deadline = time.monotonic() + self._shutdown_timeout
        owners: list[tuple[str, Callable[[], None], str]] = []
        if socket_adapter is not None:
            owners.append(
                ("socket", socket_adapter.close, "control.socket_shutdown_incomplete")
            )
        if http_adapter is not None:
            owners.append(
                (
                    "http",
                    lambda: self._close_http(http_adapter, http_thread, deadline),
                    "control.http_shutdown_incomplete",
                )
            )
        refresher = self._jwks_refresher
        if refresher_started and refresher is not None:
            owners.append(
                (
                    "jwks",
                    lambda: refresher.close(max(0.0, deadline - time.monotonic())),
                    "authority.jwks_shutdown_incomplete",
                )
            )
        failures, incomplete = self._run_owner_cleanup(owners, deadline)
        with self._state_lock:
            self._socket = socket_adapter if "socket" in incomplete else None
            self._http = http_adapter if "http" in incomplete else None
            self._http_thread = http_thread if "http" in incomplete else None
            self._incomplete_resources = incomplete
            self._ready.clear()
        return failures

    def _close_http(
        self,
        http_adapter: _HttpAdapter,
        http_thread: threading.Thread | None,
        deadline: float,
    ) -> None:
        failures: list[str] = []
        for action in (
            http_adapter.shutdown,
            lambda: self._join_http(http_thread, deadline),
            lambda: http_adapter.drain(max(0.0, deadline - time.monotonic())),
            http_adapter.server_close,
            http_adapter.close_authorities,
        ):
            try:
                action()
            except BaseException as error:
                failures.append(_failure_code(error))
        if failures:
            raise AdminDaemonShutdownError(tuple(dict.fromkeys(failures)))

    @staticmethod
    def _join_http(thread: threading.Thread | None, deadline: float) -> None:
        if thread is None:
            return
        thread.join(max(0.0, deadline - time.monotonic()))
        if thread.is_alive():
            raise RuntimeError("control.http_shutdown_incomplete")

    @staticmethod
    def _run_owner_cleanup(
        owners: Sequence[tuple[str, Callable[[], None], str]],
        deadline: float,
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        errors: dict[str, str] = {}
        threads: list[tuple[str, threading.Thread, str]] = []

        def invoke(name: str, action: Callable[[], None]) -> None:
            try:
                action()
            except BaseException as error:
                errors[name] = _failure_code(error)

        for name, action, timeout_code in owners:
            thread = threading.Thread(
                target=invoke,
                args=(name, action),
                name=f"masterjet-admin-{name}-shutdown",
                daemon=True,
            )
            threads.append((name, thread, timeout_code))
            thread.start()
        incomplete: list[str] = []
        failures: list[str] = []
        for name, thread, timeout_code in threads:
            thread.join(max(0.0, deadline - time.monotonic()))
            if thread.is_alive():
                incomplete.append(name)
                failures.append(timeout_code)
            elif name in errors:
                incomplete.append(name)
                failures.append(errors[name])
        return tuple(dict.fromkeys(failures)), tuple(incomplete)

    def stop(self) -> None:
        with self._state_lock:
            was_started = self._started
            retrying = bool(self._incomplete_resources)
            if not was_started and not retrying:
                return
            if self._stopping:
                raise AdminDaemonShutdownError(("control.admin_shutdown_incomplete",))
            self._stopping = True
            socket_adapter = self._socket
            http_adapter = self._http
            http_thread = self._http_thread
            notify_stopping = self._ready_published
            self._ready_published = False
            self._ready.clear()
        deadline = time.monotonic() + self._shutdown_timeout
        try:
            failures: list[str] = []
            if was_started and notify_stopping:
                try:
                    with self._notification_lock:
                        self._notifier("STOPPING=1")
                except BaseException as error:
                    failures.append(_failure_code(error))

            owners: list[tuple[str, Callable[[], None], str]] = []
            if socket_adapter is not None:
                owners.append(
                    (
                        "socket",
                        socket_adapter.close,
                        "control.socket_shutdown_incomplete",
                    )
                )
            if http_adapter is not None:
                owners.append(
                    (
                        "http",
                        lambda: self._close_http(http_adapter, http_thread, deadline),
                        "control.http_shutdown_incomplete",
                    )
                )
            refresher = self._jwks_refresher
            if refresher is not None and (
                was_started or "jwks" in self._incomplete_resources
            ):
                owners.append(
                    (
                        "jwks",
                        lambda: refresher.close(max(0.0, deadline - time.monotonic())),
                        "authority.jwks_shutdown_incomplete",
                    )
                )
            owner_failures, incomplete = self._run_owner_cleanup(owners, deadline)
            failures.extend(owner_failures)
            with self._state_lock:
                if was_started and self._http_failure is not None:
                    failures.append(_failure_code(self._http_failure))
                self._incomplete_resources = incomplete
                self._socket = socket_adapter if "socket" in incomplete else None
                self._http = http_adapter if "http" in incomplete else None
                self._http_thread = http_thread if "http" in incomplete else None
                self._started = False
            if failures:
                raise AdminDaemonShutdownError(tuple(dict.fromkeys(failures)))
        finally:
            with self._state_lock:
                self._stopping = False

    def run(self) -> int:
        previous: dict[int, Any] = {}

        def handle_stop(_signum: int, _frame: FrameType | None) -> None:
            self.request_stop()

        try:
            for signum in (signal.SIGTERM, signal.SIGINT):
                previous[signum] = signal.signal(signum, handle_stop)
            self.start()
            while not self._stop_requested.wait(0.1):
                pass
            self.stop()
            return 0
        except (AdminDaemonStartupError, AdminDaemonShutdownError):
            return 1
        finally:
            for restore_signum, handler in previous.items():
                signal.signal(restore_signum, handler)


def _systemd_notify(message: str) -> None:
    address = os.environ.get("NOTIFY_SOCKET")
    if not address:
        return
    endpoint = f"\0{address[1:]}" if address.startswith("@") else address
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM | socket.SOCK_CLOEXEC)
    try:
        sock.connect(endpoint)
        sock.sendall(message.encode("ascii"))
    finally:
        sock.close()


def main(argv: Sequence[str] | None = None) -> int:
    """Run the installed owner graph, emitting only stable code-only failures."""

    arguments = tuple(sys.argv[1:] if argv is None else argv)
    if arguments:
        sys.stderr.write("codex-master-admin: control.admin_arguments_invalid\n")
        return os.EX_USAGE
    try:
        from .admin_assembly import assemble_admin_runtime

        runtime = assemble_admin_runtime()
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException:
        sys.stderr.write("codex-master-admin: control.admin_configuration_invalid\n")
        return os.EX_CONFIG
    return runtime.run()


if __name__ == "__main__":
    raise SystemExit(main())
