"""Outbound-only mTLS poll client and closed host-agent executor."""

from __future__ import annotations

import argparse
from collections.abc import Mapping
from datetime import UTC, datetime
import json
import os
import ssl
import time
from typing import Protocol, cast
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPSHandler, Request, build_opener

from codex_master.agent_contracts import (
    AgentLeaseV1,
    AgentNoWorkV1,
    AgentPollV1,
    AgentReceiptV1,
    AgentResultV1,
    serialize_agent_result,
)
from codex_master.agent_ollama import AgentOllamaExecutor
from codex_master.host_agent_state import HostAgentState


BACKOFF_SECONDS = (1, 2, 5, 10, 20, 30)
MAX_RESPONSE_BYTES = 256 * 1024


class HostAgentError(RuntimeError):
    """Stable outbound-agent failure."""


def _fail(code: str) -> None:
    raise HostAgentError(code)


def _json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


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
        self._opener = build_opener(HTTPSHandler(context=context))
        if not callable(sleep):
            _fail("host.request_invalid")
        self._sleep = sleep

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
            expected = {
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
            if set(value) != expected or value["schema_version"] != 1:
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
            "schema_version": 1,
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
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        raw: bytes | None = None
        for attempt in range(len(BACKOFF_SECONDS) + 1):
            try:
                with self._opener.open(request, timeout=35) as response:
                    if (
                        response.status != 200
                        or response.headers.get_content_type() != "application/json"
                    ):
                        _fail("resource.host_response_invalid")
                    raw = response.read(MAX_RESPONSE_BYTES + 1)
                break
            except HostAgentError:
                raise
            except HTTPError:
                _fail("resource.host_response_invalid")
            except (URLError, OSError, TimeoutError):
                if attempt == len(BACKOFF_SECONDS):
                    _fail("resource.host_unreachable")
                self._sleep(BACKOFF_SECONDS[attempt])  # type: ignore[operator]
        if raw is None:
            _fail("resource.host_unreachable")
        if len(raw) > MAX_RESPONSE_BYTES:
            _fail("resource.host_response_invalid")
        try:
            result = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            _fail("resource.host_response_invalid")
        if type(result) is not dict:
            _fail("resource.host_response_invalid")
        return cast(dict[str, object], result)


class HostProbeExecutor:
    """Minimal bounded host capability collector for the Task 6 adapter seam."""

    def collect(self, value: object) -> dict[str, object]:
        """Collect only bounded, path-free local capability evidence."""
        if (
            type(value) is not dict
            or set(value) != {"probe_profile"}
            or value["probe_profile"] != "basic"
        ):
            _fail("host.arguments_invalid")
        return {"cpu_count": os.cpu_count() or 1, "status": "collected"}


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

    def dispatch(
        self, kind: str, action: str, arguments: object
    ) -> Mapping[str, object]:
        """Invoke only a statically enumerated action."""
        executors = {
            ("host.probe", "collect"): self._host_probe.collect,
            ("ollama.instance", "plan"): self._ollama.plan,
            ("ollama.instance", "apply"): self._ollama.apply,
            ("ollama.instance", "probe"): self._ollama.probe,
            ("ollama.instance", "stop"): self._ollama.stop,
        }
        executor = executors.get((kind, action))
        if executor is None:
            _fail("host.action_unsupported")
        return executor(arguments)

    def execute(self, lease: AgentLeaseV1) -> AgentReceiptV1:
        """Recover/replay safely and execute one fully fenced lease."""
        if type(lease) is not AgentLeaseV1:
            _fail("host.request_invalid")
        if lease.deadline <= datetime.now(UTC):
            _fail("host.lease_expired")
        recovered = self._state.recover(lease)
        if recovered is not None:
            return recovered
        if lease.action in {"apply", "stop"}:
            self._state.begin_effect(lease)
        try:
            payload = dict(self.dispatch(lease.kind, lease.action, lease.arguments))
        except Exception:
            result = AgentResultV1(lease.kind, lease.action, {"status": "failed"})
            return self._state.finish(
                lease,
                state="failed",
                reason_codes=("host.operation_failed",),
                result=result,
            )
        result = AgentResultV1(lease.kind, lease.action, payload)
        return self._state.finish(
            lease,
            state="succeeded",
            reason_codes=("host.operation_succeeded",),
            result=result,
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
            lease_or_idle.registry_generation != self._registry_generation
            or lease_or_idle.lease_epoch != self._lease_epoch
        ):
            _fail("host.response_fence_mismatch")
        if isinstance(lease_or_idle, AgentNoWorkV1):
            return lease_or_idle.max_wait_seconds
        receipt = self._executor.execute(lease_or_idle)
        self._client.put_receipt(receipt)
        return 0


def main(argv: list[str] | None = None) -> int:
    """Validate static non-secret service configuration for the packaged entrypoint."""
    parser = argparse.ArgumentParser(prog="codex-master-host-agent")
    parser.add_argument("--master-url", required=True)
    parser.add_argument("--host-ref", required=True)
    parser.add_argument("--registry-generation", required=True, type=int)
    parser.add_argument("--lease-epoch", required=True, type=int)
    arguments = parser.parse_args(argv)
    _master_origin(arguments.master_url)
    if arguments.registry_generation < 0 or arguments.lease_epoch < 0:
        _fail("host.request_invalid")
    if not os.environ.get("CREDENTIALS_DIRECTORY"):
        _fail("host.credentials_invalid")
    return 0


__all__ = [
    "BACKOFF_SECONDS",
    "HostAgent",
    "HostAgentClient",
    "HostAgentError",
    "HostAgentExecutor",
    "HostProbeExecutor",
    "build_tls_context",
    "main",
]
