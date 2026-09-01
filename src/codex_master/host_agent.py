"""Outbound-only mTLS poll client and closed host-agent executor."""

from __future__ import annotations

import argparse
from collections.abc import Mapping
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import re
import signal
import ssl
import stat
import threading
import time
from http.client import HTTPException, IncompleteRead
from typing import Iterator, Protocol, cast
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from codex_master.agent_contracts import (
    AgentLeaseV1,
    AgentNoWorkV1,
    AgentPollV1,
    AgentReceiptV1,
    AgentResultV1,
    serialize_agent_result,
)
from codex_master.agent_ollama import (
    AgentOllamaError,
    AgentOllamaExecutor,
    AgentOllamaNoEffectError,
    ProductionAgentOllamaAdapter,
)
from codex_master.host_agent_state import HostAgentState
from codex_master.host_probe import (
    HostProbeKernel,
    LocalHostProbeCollector,
)
from codex_master.ollama_registry import OllamaRegistryStore


BACKOFF_SECONDS = (1, 2, 5, 10, 20, 30)
MAX_RESPONSE_BYTES = 256 * 1024
MAX_CONFIG_BYTES = 64 * 1024
MAX_CREDENTIAL_BYTES = 1024 * 1024
_CREDENTIAL_NAMES = (
    "agent-config",
    "agent-master-ca",
    "agent-client-cert",
    "agent-client-key",
)
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_HOST_AGENT_STATE_ROOT = Path("/var/lib/codex-master-host-agent")
_HOST_AGENT_OLLAMA_REGISTRY = _HOST_AGENT_STATE_ROOT / "ollama" / "registry.json"


class HostAgentError(RuntimeError):
    """Stable outbound-agent failure."""


def _fail(code: str) -> None:
    raise HostAgentError(code)


def _json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ValueError


@dataclass(frozen=True, slots=True)
class HostAgentConfig:
    master_url: str
    host_ref: str
    registry_generation: int
    lease_epoch: int
    capabilities_digest: str
    state_root: Path
    ollama_registry_path: Path
    max_wait_seconds: int


@dataclass(frozen=True, slots=True)
class HostAgentCredentialFds:
    config: int
    trust: int
    certificate: int
    private_key: int

    def __iter__(self) -> Iterator[int]:
        return iter((self.config, self.trust, self.certificate, self.private_key))


class _CredentialOwner(AbstractContextManager[HostAgentCredentialFds]):
    def __init__(self, value: HostAgentCredentialFds) -> None:
        self.value = value

    def __enter__(self) -> HostAgentCredentialFds:
        return self.value

    def __exit__(self, *_error: object) -> None:
        for descriptor in self.value:
            try:
                os.close(descriptor)
            except OSError:
                pass


def open_host_agent_credentials(
    environment: Mapping[str, str],
) -> _CredentialOwner:
    """Open fixed systemd credentials relative to a verified directory FD."""
    raw_directory = environment.get("CREDENTIALS_DIRECTORY")
    if not raw_directory or not Path(raw_directory).is_absolute():
        _fail("host.credentials_invalid")
    directory_fd = -1
    opened: list[int] = []
    try:
        directory_fd = os.open(
            raw_directory,
            os.O_RDONLY
            | os.O_CLOEXEC
            | os.O_DIRECTORY
            | getattr(os, "O_NOFOLLOW", 0),
        )
        directory_stat = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(directory_stat.st_mode)
            or directory_stat.st_uid not in {0, os.geteuid()}
            or directory_stat.st_mode & 0o022
        ):
            raise OSError
        for index, name in enumerate(_CREDENTIAL_NAMES):
            descriptor = os.open(
                name,
                os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_fd,
            )
            metadata = os.fstat(descriptor)
            limit = MAX_CONFIG_BYTES if index == 0 else MAX_CREDENTIAL_BYTES
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid not in {0, os.geteuid()}
                or metadata.st_mode & 0o022
                or not 1 <= metadata.st_size <= limit
            ):
                os.close(descriptor)
                raise OSError
            opened.append(descriptor)
        return _CredentialOwner(HostAgentCredentialFds(*opened))
    except OSError:
        for descriptor in opened:
            os.close(descriptor)
        _fail("host.credentials_invalid")
    finally:
        if directory_fd >= 0:
            os.close(directory_fd)


def load_host_agent_config(descriptor: int) -> HostAgentConfig:
    """Read one bounded, exact static configuration from an already-open FD."""
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        remaining = MAX_CONFIG_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeError, ValueError, TypeError, RecursionError):
        _fail("host.config_invalid")
    expected = {
        "schema_version",
        "master_url",
        "host_ref",
        "registry_generation",
        "lease_epoch",
        "capabilities_digest",
        "state_root",
        "ollama_registry_path",
        "max_wait_seconds",
    }
    if type(document) is not dict or set(document) != expected:
        _fail("host.config_invalid")
    try:
        config = HostAgentConfig(
            master_url=_master_origin(document["master_url"]),
            host_ref=cast(str, document["host_ref"]),
            registry_generation=cast(int, document["registry_generation"]),
            lease_epoch=cast(int, document["lease_epoch"]),
            capabilities_digest=cast(str, document["capabilities_digest"]),
            state_root=Path(cast(str, document["state_root"])),
            ollama_registry_path=Path(cast(str, document["ollama_registry_path"])),
            max_wait_seconds=cast(int, document["max_wait_seconds"]),
        )
        AgentPollV1(
            config.registry_generation,
            config.lease_epoch,
            config.capabilities_digest,
            config.max_wait_seconds,
        )
    except (TypeError, ValueError):
        _fail("host.config_invalid")
    if (
        document["schema_version"] != 1
        or type(config.host_ref) is not str
        or _TOKEN.fullmatch(config.host_ref) is None
        or not config.state_root.is_absolute()
        or not config.ollama_registry_path.is_absolute()
        or config.state_root != _HOST_AGENT_STATE_ROOT
        or config.ollama_registry_path != _HOST_AGENT_OLLAMA_REGISTRY
    ):
        _fail("host.config_invalid")
    return config


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(
        self,
        request: Request,
        file_pointer: object,
        code: int,
        message: str,
        headers: object,
        new_url: str,
    ) -> None:
        del request, file_pointer, code, message, headers, new_url
        return None


def _master_origin(value: object) -> str:
    if type(value) is not str:
        _fail("host.master_url_invalid")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        _fail("host.master_url_invalid")
    return value.rstrip("/")


def build_tls_context(
    *, trust_fd: int, certificate_fd: int, key_fd: int
) -> ssl.SSLContext:
    """Build a hostname-verifying TLS 1.3 client context from open FDs."""
    if any(type(fd) is not int or fd < 0 for fd in (trust_fd, certificate_fd, key_fd)):
        _fail("host.credentials_invalid")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    try:
        context.load_verify_locations(cafile=f"/proc/self/fd/{trust_fd}")
        context.load_cert_chain(
            f"/proc/self/fd/{certificate_fd}", f"/proc/self/fd/{key_fd}"
        )
    except (OSError, ssl.SSLError):
        _fail("host.credentials_invalid")
    return context


class HostAgentClient:
    """Bounded HTTPS client pinned to one immutable Master origin."""

    def __init__(
        self,
        master_url: str,
        *,
        context: ssl.SSLContext,
        sleep: object = time.sleep,
    ) -> None:
        self.master_url = _master_origin(master_url)
        self._opener = build_opener(
            ProxyHandler({}), _NoRedirectHandler(), HTTPSHandler(context=context)
        )
        if not callable(sleep):
            _fail("host.request_invalid")
        self._sleep = sleep
        self._stop_event: threading.Event | None = None

    def set_stop_event(self, stop_event: threading.Event) -> None:
        self._stop_event = stop_event

    def poll(self, poll: AgentPollV1) -> AgentLeaseV1 | AgentNoWorkV1:
        """POST one bounded poll and parse its exact response."""
        if type(poll) is not AgentPollV1:
            _fail("host.request_invalid")
        body = {
            "schema_version": 1,
            "registry_generation": poll.registry_generation,
            "lease_epoch": poll.lease_epoch,
            "capabilities_digest": poll.capabilities_digest,
            "max_wait_seconds": poll.max_wait_seconds,
        }
        value = self._request("/agent/v1/polls", body)
        if (
            set(value)
            == {
                "schema_version",
                "registry_generation",
                "lease_epoch",
                "max_wait_seconds",
            }
            and value.get("schema_version") == 1
        ):
            try:
                return AgentNoWorkV1(
                    value["registry_generation"],
                    value["lease_epoch"],
                    value["max_wait_seconds"],
                )  # type: ignore[arg-type]
            except (TypeError, ValueError):
                _fail("resource.host_response_invalid")
        try:
            required = {
                "schema_version",
                "operation_id",
                "lease_id",
                "host_ref",
                "kind",
                "action",
                "registry_generation",
                "lease_epoch",
                "attempt",
                "plan_digest",
                "arguments_digest",
                "deadline",
                "arguments",
            }
            remote = value.get("kind") == "ollama.instance"
            remote_fields = (
                {"plan_precondition_digest", "resource_generation", "envelope_digest"}
                if remote else set()
            )
            if (
                set(value) != required | remote_fields
                or value["schema_version"] != (2 if remote else 1)
            ):
                _fail("resource.host_response_invalid")
            deadline = datetime.strptime(
                cast(str, value["deadline"]), "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=UTC)
            return AgentLeaseV1(
                deadline=deadline,
                **{
                    key: item
                    for key, item in value.items()
                    if key not in {"schema_version", "deadline"}
                },
            )  # type: ignore[arg-type]
        except (TypeError, ValueError, KeyError):
            _fail("resource.host_response_invalid")

    def put_receipt(self, receipt: AgentReceiptV1) -> None:
        """Submit one semantic receipt without translating it to transport success."""
        if type(receipt) is not AgentReceiptV1:
            _fail("host.request_invalid")
        body = {
            "schema_version": 2 if receipt.result.kind == "ollama.instance" else 1,
            "operation_id": receipt.operation_id,
            "lease_id": receipt.lease_id,
            "lease_epoch": receipt.lease_epoch,
            "attempt": receipt.attempt,
            "plan_digest": receipt.plan_digest,
            "arguments_digest": receipt.arguments_digest,
            "state": receipt.state,
            "reason_codes": list(receipt.reason_codes),
            "result_digest": receipt.result_digest,
            "result": serialize_agent_result(receipt.result),
        }
        if receipt.result.kind == "ollama.instance":
            body["envelope_digest"] = receipt.envelope_digest
        response = self._request(
            f"/agent/v1/operations/{receipt.operation_id}/receipts", body
        )
        if response != {
            "schema_version": 1,
            "operation_id": receipt.operation_id,
            "accepted": True,
        }:
            _fail("resource.host_response_invalid")

    def _request(self, target: str, value: object) -> dict[str, object]:
        request = Request(
            self.master_url + target,
            data=_json(value),
            headers={"Content-Type": "application/json", "Connection": "close"},
            method="POST",
        )
        raw: bytes | None = None
        for attempt in range(len(BACKOFF_SECONDS) + 1):
            try:
                with self._opener.open(request, timeout=35) as response:
                    content_types = response.headers.get_all("Content-Type") or []
                    content_lengths = response.headers.get_all("Content-Length") or []
                    transfer_encodings = response.headers.get_all("Transfer-Encoding") or []
                    if response.status != 200 or response.geturl() != request.full_url:
                        _fail("resource.host_response_invalid")
                    if (
                        content_types != ["application/json"]
                        or len(content_lengths) != 1
                        or transfer_encodings
                    ):
                        _fail("resource.host_response_invalid")
                    content_length = content_lengths[0]
                    if (
                        type(content_length) is not str
                        or not content_length.isascii()
                        or not content_length.isdecimal()
                        or not 1 <= int(content_length) <= MAX_RESPONSE_BYTES
                    ):
                        _fail("resource.host_response_invalid")
                    expected_length = int(content_length)
                    try:
                        stream = getattr(response, "fp", None)
                        raw = (
                            stream.read(expected_length + 1)
                            if stream is not None
                            else response.read(expected_length + 1)
                        )
                    except (IncompleteRead, HTTPException):
                        _fail("resource.host_response_invalid")
                    if len(raw) != expected_length:
                        _fail("resource.host_response_invalid")
                break
            except HostAgentError:
                raise
            except HTTPError:
                _fail("resource.host_response_invalid")
            except (URLError, OSError, TimeoutError):
                if attempt == len(BACKOFF_SECONDS):
                    _fail("resource.host_unreachable")
                delay = BACKOFF_SECONDS[attempt]
                if self._stop_event is not None:
                    if self._stop_event.wait(delay):
                        _fail("host.operation_interrupted")
                else:
                    self._sleep(delay)  # type: ignore[operator]
        if raw is None:
            _fail("resource.host_unreachable")
        if len(raw) > MAX_RESPONSE_BYTES:
            _fail("resource.host_response_invalid")
        try:
            result = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_strict_object,
                parse_constant=_reject_constant,
            )
        except (UnicodeError, ValueError, TypeError, RecursionError):
            _fail("resource.host_response_invalid")
        if type(result) is not dict:
            _fail("resource.host_response_invalid")
        return cast(dict[str, object], result)


class HostProbeExecutor:
    """Execute the one fixed Task-6 probe contract with canonical evidence."""

    def __init__(
        self,
        *,
        collector: LocalHostProbeCollector | None = None,
        kernel: HostProbeKernel | None = None,
    ) -> None:
        self._collector = collector or LocalHostProbeCollector()
        self._kernel = kernel

    @staticmethod
    def validate(value: object) -> None:
        """Validate the exact private owner arguments without collecting facts."""
        if not isinstance(value, Mapping) or set(value) != {
            "admin_operation_id",
            "probe_schema",
        }:
            _fail("host.arguments_invalid")
        operation_id = value["admin_operation_id"]
        if (
            type(operation_id) is not str
            or _TOKEN.fullmatch(operation_id) is None
            or type(value["probe_schema"]) is not int
            or value["probe_schema"] != 1
        ):
            _fail("host.arguments_invalid")

    def collect(self, value: object) -> dict[str, object]:
        """Collect only bounded, path-free local capability evidence."""
        self.validate(value)
        return self._collector.collect(self._kernel).public()


class HostAgentExecutor:
    """Fixed dispatch with durable mutating-effect boundaries."""

    def __init__(
        self,
        *,
        state: HostAgentState,
        ollama: object,
        host_probe: HostProbeExecutor | None = None,
    ) -> None:
        self._state = state
        self._ollama = AgentOllamaExecutor(ollama)  # type: ignore[arg-type]
        self._host_probe = host_probe or HostProbeExecutor()
        self._stop_event: threading.Event | None = None

    def set_stop_event(self, stop_event: threading.Event) -> None:
        self._stop_event = stop_event

    def validate(self, kind: str, action: str, arguments: object) -> None:
        if kind == "ollama.instance":
            self._ollama.validate(action, arguments)
        elif kind == "host.probe" and action == "collect":
            self._host_probe.validate(arguments)
        else:
            _fail("host.action_unsupported")

    def dispatch(
        self,
        kind: str,
        action: str,
        arguments: object,
        *,
        plan_precondition_digest: str | None = None,
        resource_generation: int | None = None,
    ) -> Mapping[str, object]:
        """Invoke only a statically enumerated action."""
        if kind == "host.probe" and action == "collect":
            return self._host_probe.collect(arguments)
        if kind != "ollama.instance":
            _fail("host.action_unsupported")
        executors = {
            "plan": self._ollama.plan,
            "apply": self._ollama.apply,
            "probe": self._ollama.probe,
            "stop": self._ollama.stop,
        }
        executor = executors.get(action)
        if executor is None:
            _fail("host.action_unsupported")
        return executor(
            arguments,
            plan_precondition_digest=plan_precondition_digest,
            resource_generation=resource_generation,
        )

    def execute(self, lease: AgentLeaseV1) -> AgentReceiptV1:
        """Recover/replay safely and execute one fully fenced lease."""
        if type(lease) is not AgentLeaseV1:
            _fail("host.request_invalid")
        if lease.deadline <= datetime.now(UTC):
            _fail("host.lease_expired")
        try:
            self.validate(lease.kind, lease.action, lease.arguments)
        except AgentOllamaError as error:
            _fail(str(error))
        recovered = self._state.recover(lease, stop_event=self._stop_event)
        if recovered is not None:
            return recovered
        mutating = (lease.kind, lease.action) in {
            ("ollama.instance", "apply"),
            ("ollama.instance", "stop"),
        }
        claim_token = self._state.begin_effect(lease) if mutating else None
        if mutating and claim_token is None:
            concurrent = self._state.recover(lease, stop_event=self._stop_event)
            if concurrent is None:
                _fail("host.effect_claim_lost")
            return concurrent
        try:
            payload = dict(
                self.dispatch(
                    lease.kind,
                    lease.action,
                    lease.arguments,
                    plan_precondition_digest=lease.plan_precondition_digest,
                    resource_generation=lease.resource_generation,
                )
            )
        except AgentOllamaNoEffectError:
            result = AgentResultV1(
                lease.kind, lease.action, {"status": "failed"}
            )
            return self._state.finish(
                lease,
                state="failed",
                reason_codes=("host.operation_failed",),
                result=result,
                claim_token=claim_token,
            )
        except Exception:
            unknown = mutating
            result = AgentResultV1(
                lease.kind,
                lease.action,
                {"status": "effect_unknown" if unknown else "failed"},
            )
            return self._state.finish(
                lease,
                state="unknown" if unknown else "failed",
                reason_codes=(
                    "host.operation_unknown" if unknown else "host.operation_failed",
                ),
                result=result,
                claim_token=claim_token,
            )
        result = AgentResultV1(lease.kind, lease.action, payload)
        return self._state.finish(
            lease,
            state="succeeded",
            reason_codes=("host.operation_succeeded",),
            result=result,
            claim_token=claim_token,
        )


class _Client(Protocol):
    def poll(self, poll: AgentPollV1) -> AgentLeaseV1 | AgentNoWorkV1: ...
    def put_receipt(self, receipt: AgentReceiptV1) -> None: ...


class _Executor(Protocol):
    def execute(self, lease: AgentLeaseV1) -> AgentReceiptV1: ...


class HostAgent:
    """Single-iteration outbound pull loop."""

    def __init__(
        self,
        *,
        client: _Client,
        executor: _Executor,
        registry_generation: int,
        lease_epoch: int,
        capabilities_digest: str,
    ) -> None:
        self._client = client
        self._executor = executor
        self._registry_generation = registry_generation
        self._lease_epoch = lease_epoch
        self._capabilities_digest = capabilities_digest

    def set_stop_event(self, stop_event: threading.Event) -> None:
        for target in (self._client, self._executor):
            setter = getattr(target, "set_stop_event", None)
            if callable(setter):
                setter(stop_event)

    def _poll(self, max_wait_seconds: int) -> AgentPollV1:
        return AgentPollV1(
            self._registry_generation,
            self._lease_epoch,
            self._capabilities_digest,
            max_wait_seconds,
        )

    def run_once(self, *, max_wait_seconds: int = 20) -> int:
        """Poll once, execute work, and durably submit its semantic receipt."""
        lease_or_idle = self._client.poll(self._poll(max_wait_seconds))
        if (
            lease_or_idle.registry_generation < self._registry_generation
            or lease_or_idle.lease_epoch != self._lease_epoch
        ):
            _fail("host.response_fence_mismatch")
        self._registry_generation = lease_or_idle.registry_generation
        if isinstance(lease_or_idle, AgentNoWorkV1):
            return lease_or_idle.max_wait_seconds
        receipt = self._executor.execute(lease_or_idle)
        self._client.put_receipt(receipt)
        return 0


def assemble_host_agent(
    credentials: HostAgentCredentialFds,
) -> tuple[HostAgent, HostAgentConfig]:
    """Assemble all production dependencies from owned credential descriptors."""
    config = load_host_agent_config(credentials.config)
    context = build_tls_context(
        trust_fd=credentials.trust,
        certificate_fd=credentials.certificate,
        key_fd=credentials.private_key,
    )
    state = HostAgentState(config.state_root, host_ref=config.host_ref)
    registry = OllamaRegistryStore(config.ollama_registry_path)
    executor = HostAgentExecutor(
        state=state,
        ollama=ProductionAgentOllamaAdapter(registry, state_root=config.state_root),
    )
    return (
        HostAgent(
            client=HostAgentClient(config.master_url, context=context),
            executor=executor,
            registry_generation=config.registry_generation,
            lease_epoch=config.lease_epoch,
            capabilities_digest=config.capabilities_digest,
        ),
        config,
    )


def run_poll_loop(
    agent: HostAgent,
    *,
    max_wait_seconds: int,
    stop_event: threading.Event,
) -> None:
    """Run until signalled, with interruptible server-requested idle waits."""
    setter = getattr(agent, "set_stop_event", None)
    if callable(setter):
        setter(stop_event)
    while not stop_event.is_set():
        try:
            delay = agent.run_once(max_wait_seconds=max_wait_seconds)
        except HostAgentError:
            if stop_event.is_set():
                return
            stop_event.wait(BACKOFF_SECONDS[0])
            continue
        if delay > 0:
            stop_event.wait(delay)


def main(argv: list[str] | None = None) -> int:
    """Run the packaged outbound agent using only fixed systemd credentials."""
    parser = argparse.ArgumentParser(prog="codex-master-host-agent")
    parser.parse_args(argv)
    stop_event = threading.Event()

    def stop(_number: int, _frame: object) -> None:
        stop_event.set()

    previous = {
        number: signal.signal(number, stop)
        for number in (signal.SIGINT, signal.SIGTERM)
    }
    try:
        with open_host_agent_credentials(os.environ) as credentials:
            agent, config = assemble_host_agent(credentials)
            run_poll_loop(
                agent,
                max_wait_seconds=config.max_wait_seconds,
                stop_event=stop_event,
            )
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
    return 0


__all__ = [
    "BACKOFF_SECONDS",
    "HostAgent",
    "HostAgentClient",
    "HostAgentError",
    "HostAgentExecutor",
    "HostAgentConfig",
    "HostAgentCredentialFds",
    "HostProbeExecutor",
    "assemble_host_agent",
    "build_tls_context",
    "load_host_agent_config",
    "main",
    "open_host_agent_credentials",
    "run_poll_loop",
]
