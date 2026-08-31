from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import ssl
from urllib.error import URLError

import pytest

from codex_master.agent_contracts import (
    AgentLeaseV1,
    AgentNoWorkV1,
    AgentPollV1,
    AgentResultV1,
)
from codex_master.host_agent import (
    BACKOFF_SECONDS,
    MAX_RESPONSE_BYTES,
    HostAgent,
    HostAgentClient,
    HostAgentError,
    HostAgentExecutor,
    HostProbeExecutor,
    build_tls_context,
    main,
)
from codex_master.host_agent_state import HostAgentState, HostAgentStateError


def digest(value: object) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )


def lease(**changes: object) -> AgentLeaseV1:
    args = changes.pop("arguments", {"plan_ref": "plan-one"})
    values: dict[str, object] = {
        "operation_id": "operation-one",
        "lease_id": "lease-one",
        "host_ref": "worker-one",
        "kind": "ollama.instance",
        "action": "apply",
        "registry_generation": 7,
        "lease_epoch": 3,
        "attempt": 1,
        "plan_digest": "sha256:" + "a" * 64,
        "arguments_digest": digest(args),
        "deadline": datetime(2099, 1, 1, tzinfo=UTC),
        "arguments": args,
    }
    values.update(changes)
    return AgentLeaseV1(**values)  # type: ignore[arg-type]


class Ollama:
    def __init__(self) -> None:
        self.apply_calls = 0

    def apply(self, arguments: object) -> dict[str, object]:
        self.apply_calls += 1
        return {"instance_ref": "one"}


def test_same_operation_returns_receipt_without_second_effect(tmp_path: Path) -> None:
    runtime = Ollama()
    state = HostAgentState.for_test(tmp_path, host_ref="worker-one")
    executor = HostAgentExecutor(state=state, ollama=runtime)
    first = executor.execute(lease())
    second = executor.execute(lease())
    assert second == first and runtime.apply_calls == 1


def test_dispatch_is_closed_and_begin_effect_precedes_mutation(tmp_path: Path) -> None:
    events: list[str] = []

    class State(HostAgentState):
        def begin_effect(self, item: AgentLeaseV1) -> None:
            super().begin_effect(item)
            events.append("durable")

    class Ordered(Ollama):
        def apply(self, arguments: object) -> dict[str, object]:
            events.append("effect")
            return super().apply(arguments)

    executor = HostAgentExecutor(
        state=State.for_test(tmp_path, host_ref="worker-one"), ollama=Ordered()
    )
    executor.execute(lease())
    assert events == ["durable", "effect"]
    with pytest.raises(HostAgentError, match="host.action_unsupported"):
        executor.dispatch("unknown", "run", {})


def test_expired_lease_is_rejected_before_state_or_effect(tmp_path: Path) -> None:
    runtime = Ollama()
    executor = HostAgentExecutor(
        state=HostAgentState.for_test(tmp_path, host_ref="worker-one"), ollama=runtime
    )
    with pytest.raises(HostAgentError, match="host.lease_expired"):
        executor.execute(lease(deadline=datetime(2020, 1, 1, tzinfo=UTC)))
    assert runtime.apply_calls == 0


def test_finish_failure_propagates_without_second_finish(tmp_path: Path) -> None:
    class FailingState(HostAgentState):
        finish_calls = 0

        def finish(self, *args: object, **kwargs: object) -> object:
            self.finish_calls += 1
            raise HostAgentStateError("host.state_unavailable")

    state = FailingState.for_test(tmp_path, host_ref="worker-one")
    executor = HostAgentExecutor(state=state, ollama=Ollama())
    with pytest.raises(HostAgentStateError, match="host.state_unavailable"):
        executor.execute(lease())
    assert state.finish_calls == 1


def test_run_once_polls_executes_receipt_and_honors_idle() -> None:
    class Client:
        def __init__(self, response: object) -> None:
            self.response = response
            self.receipts = []

        def poll(self, poll: object) -> object:
            return self.response

        def put_receipt(self, receipt: object) -> None:
            self.receipts.append(receipt)

    class Executor:
        def execute(self, item: AgentLeaseV1) -> AgentResultV1:
            return AgentResultV1("ollama.instance", "apply", {"ok": True})

    idle = Client(AgentNoWorkV1(7, 3, 5))
    agent = HostAgent(
        client=idle,
        executor=Executor(),
        registry_generation=7,
        lease_epoch=3,
        capabilities_digest="sha256:" + "c" * 64,
    )
    assert agent.run_once() == 5
    busy = Client(lease())
    agent = HostAgent(
        client=busy,
        executor=Executor(),
        registry_generation=7,
        lease_epoch=3,
        capabilities_digest="sha256:" + "c" * 64,
    )
    assert agent.run_once() == 0 and len(busy.receipts) == 1

    wrong_generation = Client(AgentNoWorkV1(8, 3, 5))
    agent = HostAgent(
        client=wrong_generation,
        executor=Executor(),
        registry_generation=7,
        lease_epoch=3,
        capabilities_digest="sha256:" + "c" * 64,
    )
    with pytest.raises(HostAgentError, match="host.response_fence_mismatch"):
        agent.run_once()


def test_tls_context_and_static_url_and_backoff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, str]] = []

    class Context:
        minimum_version = None
        check_hostname = False
        verify_mode = None

        def load_verify_locations(self, *, cafile: str) -> None:
            calls.append(("ca", cafile))

        def load_cert_chain(self, certfile: str, keyfile: str) -> None:
            calls.extend((("cert", certfile), ("key", keyfile)))

    monkeypatch.setattr(ssl, "SSLContext", lambda protocol: Context())
    context = build_tls_context(trust_fd=10, certificate_fd=11, key_fd=12)
    assert (
        context.minimum_version == ssl.TLSVersion.TLSv1_3
        and context.check_hostname
        and context.verify_mode == ssl.CERT_REQUIRED
    )
    assert calls == [
        ("ca", "/proc/self/fd/10"),
        ("cert", "/proc/self/fd/11"),
        ("key", "/proc/self/fd/12"),
    ]
    client = HostAgentClient("https://master.internal:9443", context=context)
    assert client.master_url == "https://master.internal:9443" and BACKOFF_SECONDS == (
        1,
        2,
        5,
        10,
        20,
        30,
    )
    with pytest.raises(HostAgentError, match="host.master_url_invalid"):
        HostAgentClient("http://master.internal", context=context)
    with pytest.raises(HostAgentError, match="host.master_url_invalid"):
        HostAgentClient(None, context=context)  # type: ignore[arg-type]


def test_client_parses_bounded_poll_and_receipt_and_retries_transport(
    tmp_path: Path,
) -> None:
    class Headers:
        @staticmethod
        def get_content_type() -> str:
            return "application/json"

    class Response:
        status = 200
        headers = Headers()

        def __init__(self, body: object) -> None:
            self.body = json.dumps(body).encode()

        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self, maximum: int) -> bytes:
            return self.body[:maximum]

    class Opener:
        def __init__(self) -> None:
            self.calls = 0
            self.body: object = {
                "schema_version": 1,
                "registry_generation": 7,
                "lease_epoch": 3,
                "max_wait_seconds": 5,
            }

        def open(self, request: object, timeout: int) -> Response:
            self.calls += 1
            if self.calls <= 2:
                raise URLError("offline")
            return Response(self.body)

    delays: list[int] = []
    client = HostAgentClient(
        "https://master.internal",
        context=ssl.create_default_context(),
        sleep=delays.append,
    )
    opener = Opener()
    client._opener = opener  # type: ignore[attr-defined]
    idle = client.poll(AgentPollV1(7, 3, "sha256:" + "c" * 64, 5))
    assert isinstance(idle, AgentNoWorkV1)
    assert delays == [1, 2]
    receipt = HostAgentExecutor(
        state=HostAgentState.for_test(tmp_path, host_ref="worker-one"),
        ollama=Ollama(),
    ).execute(lease())
    opener.body = {
        "schema_version": 1,
        "operation_id": receipt.operation_id,
        "accepted": True,
    }
    client.put_receipt(receipt)


def test_client_enforces_full_backoff_response_bound_and_exact_idle_type() -> None:
    class Offline:
        def open(self, request: object, timeout: int) -> object:
            raise URLError("offline")

    delays: list[int] = []
    client = HostAgentClient(
        "https://master.internal",
        context=ssl.create_default_context(),
        sleep=delays.append,
    )
    client._opener = Offline()  # type: ignore[attr-defined]
    with pytest.raises(HostAgentError, match="resource.host_unreachable"):
        client.poll(AgentPollV1(7, 3, "sha256:" + "c" * 64, 5))
    assert delays == list(BACKOFF_SECONDS)

    class Headers:
        @staticmethod
        def get_content_type() -> str:
            return "application/json"

    class Response:
        status = 200
        headers = Headers()

        def __init__(self, body: bytes) -> None:
            self.body = body

        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self, maximum: int) -> bytes:
            return self.body[:maximum]

    class Fixed:
        def __init__(self, body: bytes) -> None:
            self.body = body

        def open(self, request: object, timeout: int) -> Response:
            return Response(self.body)

    client._opener = Fixed(b" " * (MAX_RESPONSE_BYTES + 1))  # type: ignore[attr-defined]
    with pytest.raises(HostAgentError, match="resource.host_response_invalid"):
        client.poll(AgentPollV1(7, 3, "sha256:" + "c" * 64, 5))

    malformed_idle = json.dumps(
        {
            "schema_version": 1,
            "registry_generation": True,
            "lease_epoch": 3,
            "max_wait_seconds": 5,
        }
    ).encode()
    client._opener = Fixed(malformed_idle)  # type: ignore[attr-defined]
    with pytest.raises(HostAgentError, match="resource.host_response_invalid"):
        client.poll(AgentPollV1(7, 3, "sha256:" + "c" * 64, 5))


def test_host_probe_and_cli_configuration_are_executed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert (
        HostProbeExecutor().collect({"probe_profile": "basic"})["status"] == "collected"
    )
    with pytest.raises(HostAgentError, match="host.arguments_invalid"):
        HostProbeExecutor().collect({"probe_profile": "free"})
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", "/run/credentials/service")
    assert (
        main(
            [
                "--master-url",
                "https://master.internal",
                "--host-ref",
                "worker-one",
                "--registry-generation",
                "7",
                "--lease-epoch",
                "3",
            ]
        )
        == 0
    )
    with pytest.raises(HostAgentError, match="host.master_url_invalid"):
        main(
            [
                "--master-url",
                "http://master.internal",
                "--host-ref",
                "worker-one",
                "--registry-generation",
                "7",
                "--lease-epoch",
                "3",
            ]
        )
