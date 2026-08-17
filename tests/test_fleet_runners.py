from __future__ import annotations

import io
import json
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

from codex_master.fleet_registry import AgentDescriptor, Provider, RunnerKind
from codex_master.fleet_runners import (
    FleetRunnerError,
    HUGGINGFACE_MODELS_URL,
    MAX_PROVIDER_RESPONSE_BYTES,
    OLLAMA_MODELS_URL,
    build_runner_plan,
    classify_provider_error,
    model_is_agentic,
    parse_gemini_jsonl,
    probe_gemini_cli,
    probe_huggingface_models,
    probe_ollama_models,
)


class _ProbeProcess:
    def __init__(self, stdout: bytes) -> None:
        self.pid = 74231
        self.stdin = io.BytesIO()
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO()
        self._returncode = 0

    def poll(self) -> int:
        return self._returncode

    def wait(self) -> int:
        return self._returncode


def agent(tmp_path: Path, provider: Provider, runner: RunnerKind, *, account_id: str | None) -> AgentDescriptor:
    return AgentDescriptor(
        "d1", "d", 1, "Test agent", runner, provider, "gemini-3-flash-preview", account_id,
        tmp_path / "agents" / "d1", "codex_agent_d1_mcp", True,
    )


def test_codex_runner_keeps_chatgpt_home_and_unsets_foreign_secrets(tmp_path: Path) -> None:
    plan = build_runner_plan(
        agent(tmp_path, Provider.OPENAI_CHATGPT, RunnerKind.CODEX_CLI, account_id="chatgpt"),
        Path("/usr/local/bin/codex"),
    )

    assert plan.mode == "persistent_tui"
    assert plan.argv == ("/usr/local/bin/codex", "-m", "gemini-3-flash-preview")
    assert plan.env["CODEX_HOME"] == str(tmp_path / "agents" / "d1")
    assert plan.secret_env_name is None
    assert "OPENAI_API_KEY" in plan.unset_env
    assert "GEMINI_API_KEY" in plan.unset_env


def test_openai_api_runner_allows_only_its_secret_name(tmp_path: Path) -> None:
    plan = build_runner_plan(
        agent(tmp_path, Provider.OPENAI_API, RunnerKind.CODEX_CLI, account_id="openai"),
        Path("/usr/local/bin/codex"),
    )

    assert plan.secret_env_name == "OPENAI_API_KEY"
    assert "OPENAI_API_KEY" not in plan.unset_env
    assert "HF_TOKEN" in plan.unset_env


def test_ollama_runner_uses_codex_builtin_provider_without_secret(tmp_path: Path) -> None:
    plan = build_runner_plan(
        agent(tmp_path, Provider.OLLAMA_LOCAL, RunnerKind.CODEX_CLI, account_id=None),
        Path("/usr/local/bin/codex"),
    )
    assert plan.argv == ("/usr/local/bin/codex", "-m", "gemini-3-flash-preview")
    assert plan.secret_env_name is None
    assert "OPENAI_API_KEY" in plan.unset_env


def test_hf_runner_uses_responses_profile_and_env_reference(tmp_path: Path) -> None:
    plan = build_runner_plan(
        agent(tmp_path, Provider.HUGGINGFACE_INFERENCE, RunnerKind.CODEX_CLI, account_id="hf"),
        Path("/usr/local/bin/codex"),
    )

    assert plan.secret_env_name == "HF_TOKEN"
    assert "https://router.huggingface.co/v1" in " ".join(plan.argv)
    assert 'env_key="HF_TOKEN"' in " ".join(plan.argv)
    assert not hasattr(plan, "secret_value")


def test_gemini_runner_is_headless_jsonl_and_home_isolated(tmp_path: Path) -> None:
    plan = build_runner_plan(
        agent(tmp_path, Provider.GEMINI_API, RunnerKind.GEMINI_CLI, account_id="gemini-project-1"),
        Path("/usr/local/bin/gemini"),
    )

    assert plan.mode == "headless_job"
    assert plan.argv == (
        "/usr/local/bin/gemini", "--output-format", "stream-json", "--model",
        "gemini-3-flash-preview", "--prompt", "",
    )
    assert "private task" not in plan.argv
    assert plan.env == {
        "HOME": str(tmp_path / "agents" / "d1"),
        "GEMINI_CLI_HOME": str(tmp_path / "agents" / "d1"),
        "GEMINI_CLI_TRUST_WORKSPACE": "true",
    }
    assert plan.secret_env_name == "GEMINI_API_KEY"
    assert "OPENAI_API_KEY" in plan.unset_env
    assert {"GOOGLE_API_KEY", "GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_CLOUD_PROJECT",
            "GOOGLE_CLOUD_LOCATION", "GOOGLE_GENAI_USE_VERTEXAI"} <= plan.unset_env

    lightweight = build_runner_plan(
        replace(agent(tmp_path, Provider.GEMINI_API, RunnerKind.GEMINI_CLI, account_id="gemini-project-1"), model="auto"),
        Path("/usr/local/bin/gemini"),
    )
    assert "gemini-3.1-flash-lite" in lightweight.argv


def test_gemini_provider_probe_is_stdin_only_bounded_and_isolated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "gemini"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o700)
    captured: dict[str, object] = {}

    def launch(argv: tuple[str, ...], **kwargs: object) -> _ProbeProcess:
        captured["argv"] = argv
        captured["env"] = dict(kwargs["env"])  # type: ignore[arg-type]
        settings_path = Path(captured["env"]["GEMINI_CLI_HOME"]) / ".gemini" / "settings.json"  # type: ignore[index]
        captured["settings"] = settings_path.read_text(encoding="utf-8")
        return _ProbeProcess(
            b'{"type":"init","model":"gemini-3-flash-preview"}\n'
            b'{"type":"result","response":"OK"}\n',
        )

    monkeypatch.setenv("OPENAI_API_KEY", "foreign-secret")
    monkeypatch.setenv("GOOGLE_API_KEY", "foreign-secret")
    result = probe_gemini_cli(
        "private-gemini-secret",
        executable,
        popen_factory=launch,
    )

    assert result.ok is True
    assert result.model == "gemini-3-flash-preview"
    assert result.supports_tools is True
    argv = captured["argv"]
    assert isinstance(argv, tuple)
    assert "private-gemini-secret" not in argv
    assert "Reply with exactly OK. Do not modify files or use tools." not in argv
    assert "--prompt" in argv
    assert "--approval-mode=plan" in argv
    assert "gemini-3.1-flash-lite" in argv
    settings = json.loads(captured["settings"])  # type: ignore[arg-type]
    assert settings["general"]["maxAttempts"] == 1
    assert settings["general"]["retryFetchErrors"] is False
    env = captured["env"]
    assert isinstance(env, dict)
    assert env["GEMINI_API_KEY"] == "private-gemini-secret"
    assert env["GEMINI_CLI_TRUST_WORKSPACE"] == "true"
    assert "OPENAI_API_KEY" not in env
    assert "GOOGLE_API_KEY" not in env
    assert '"enforcedType": "gemini-api-key"' in captured["settings"]
    assert "private-gemini-secret" not in repr(result)


def test_runner_plan_is_immutable_and_refuses_relative_or_controlled_executable(tmp_path: Path) -> None:
    valid_agent = agent(tmp_path, Provider.OLLAMA_LOCAL, RunnerKind.CODEX_CLI, account_id=None)
    plan = build_runner_plan(valid_agent, Path("/usr/local/bin/codex"))
    with pytest.raises(TypeError):
        plan.env["X"] = "value"  # type: ignore[index]
    with pytest.raises(FrozenInstanceError):
        plan.argv = ()  # type: ignore[misc]
    for executable in (Path("codex"), Path("/usr/local/bin/co\nex")):
        with pytest.raises(FleetRunnerError):
            build_runner_plan(valid_agent, executable)


def test_runner_plan_constructor_freezes_nested_collections(tmp_path: Path) -> None:
    valid_agent = agent(tmp_path, Provider.OLLAMA_LOCAL, RunnerKind.CODEX_CLI, account_id=None)
    plan = build_runner_plan(valid_agent, Path("/usr/local/bin/codex"))
    direct = type(plan)(plan.mode, list(plan.argv), dict(plan.env), set(plan.unset_env), plan.secret_env_name)
    with pytest.raises(TypeError):
        direct.env["X"] = "value"  # type: ignore[index]
    with pytest.raises(AttributeError):
        direct.argv.append("unexpected")  # type: ignore[attr-defined]


def test_gemini_parser_keeps_only_assistant_response_and_aggregate_usage() -> None:
    result = parse_gemini_jsonl([
        '{"type":"init","session_id":"session-1","model":"gemini-3-flash-preview"}',
        '{"type":"message","role":"user","content":"private user prompt"}',
        '{"type":"tool_use","parameters":{"private":"argument"}}',
        '{"type":"tool_result","output":"private tool output"}',
        '{"type":"message","role":"assistant","content":"first "}',
        '{"type":"message","role":"assistant","content":"answer"}',
        '{"type":"result","stats":{"input_tokens":12,"output_tokens":7}}',
    ])

    assert result.response == "first answer"
    assert result.session_id == "session-1"
    assert result.model == "gemini-3-flash-preview"
    assert (result.input_tokens, result.output_tokens, result.tool_call_count) == (12, 7, 1)
    assert result.event_count == 7
    assert result.unknown_event_count == 0
    assert result.error is None
    assert "private" not in repr(result)


def test_gemini_parser_accepts_final_response_and_counts_unknown_events() -> None:
    result = parse_gemini_jsonl([
        '{"type":"init","session_id":"session-1","model":"gemini-3-flash-preview"}',
        '{"type":"new_event","prompt":"private"}',
        '{"type":"result","response":"final answer","stats":{"input_tokens":0,"output_tokens":2}}',
    ])

    assert result.response == "final answer"
    assert result.unknown_event_count == 1


@pytest.mark.parametrize("lines", [
    ['{"type":"init"}'],
    ["not json"],
    ["[]"],
    ['{"type":"result","stats":{"input_tokens":-1}}'],
    ['{"type":"result","stats":{"output_tokens":9223372036854775808}}'],
    ["\ud800"],
    ["x" * (1024 * 1024 + 1)],
    ['{"type":"message","role":"assistant","content":"' + "x" * (1024 * 1024 + 1) + '"}',
     '{"type":"result"}'],
])
def test_gemini_parser_rejects_malformed_or_bounded_streams(lines: list[str]) -> None:
    with pytest.raises(FleetRunnerError):
        parse_gemini_jsonl(lines)


def test_gemini_parser_rejects_more_than_ten_thousand_events() -> None:
    lines = ['{"type":"unknown"}'] * 10_000 + ['{"type":"result"}']
    with pytest.raises(FleetRunnerError):
        parse_gemini_jsonl(lines)


def test_gemini_parser_enforces_one_response_budget_across_chunks_and_result() -> None:
    response_part = "x" * 700_000
    with pytest.raises(FleetRunnerError):
        parse_gemini_jsonl([
            '{"type":"message","role":"assistant","content":"' + response_part + '"}',
            '{"type":"result","response":"' + response_part + '"}',
        ])


def test_gemini_parser_returns_data_minimized_structured_provider_error() -> None:
    result = parse_gemini_jsonl([
        '{"type":"error","error":{"code":429,"status":"RESOURCE_EXHAUSTED",'
        '"message":"private provider diagnosis"}}',
        '{"type":"result"}',
    ])

    assert result.error is not None
    assert result.error.kind == "account_limited"
    assert result.error.status_code == 429
    assert "private" not in repr(result)


def test_resource_exhausted_is_shared_account_limit() -> None:
    error = classify_provider_error(
        Provider.GEMINI_API, {"error": {"code": 429, "status": "RESOURCE_EXHAUSTED"}}, "",
    )

    assert error.kind == "account_limited"
    assert error.retryable is True


def test_stderr_alone_never_marks_an_account_limited() -> None:
    error = classify_provider_error(Provider.GEMINI_API, None, "quota exhausted private details")
    assert error.kind == "runner_failed"
    assert error.status_code is None


@pytest.mark.parametrize(("payload", "kind", "retryable"), [
    ({"code": 401}, "auth_invalid", False),
    ({"status": "UNAVAILABLE"}, "provider_unavailable", True),
    ({"error": {"code": 503}}, "provider_unavailable", True),
    ({"status": "MODEL_NOT_FOUND"}, "model_unavailable", False),
    ({"message": "private unknown failure"}, "runner_failed", False),
])
def test_provider_error_classifier_uses_only_structured_confirmations(
    payload: object, kind: str, retryable: bool
) -> None:
    error = classify_provider_error(Provider.OPENAI_API, payload, "private stderr")
    assert (error.kind, error.retryable) == (kind, retryable)


def test_provider_error_keeps_only_valid_structured_reset_time() -> None:
    valid = classify_provider_error(
        Provider.GEMINI_API, {"code": 429, "reset_at_utc": "2026-08-03T12:00:00Z"}, "",
    )
    invalid = classify_provider_error(
        Provider.GEMINI_API, {"code": 429, "reset_at_utc": "private reset date"}, "",
    )
    assert valid.reset_at_utc == "2026-08-03T12:00:00Z"
    assert invalid.reset_at_utc is None


def test_provider_error_rejects_non_rfc3339_structured_reset_time() -> None:
    error = classify_provider_error(
        Provider.GEMINI_API, {"code": 429, "reset_at_utc": "2026-08-03T12:00Z"}, "",
    )
    assert error.reset_at_utc is None


@pytest.mark.parametrize(("provider", "metadata", "expected"), [
    (Provider.OLLAMA_LOCAL, {"installed": True, "supports_tools": True}, True),
    (Provider.OLLAMA_LOCAL, {"installed": True, "supports_tools": False}, False),
    (Provider.OLLAMA_LOCAL, {"installed": "true"}, False),
    (Provider.HUGGINGFACE_INFERENCE,
     {"supports_tools": True, "supports_responses": True, "provider_available": True}, True),
    (Provider.HUGGINGFACE_INFERENCE,
     {"supports_tools": True, "supports_responses": "true", "provider_available": True}, False),
    (Provider.GEMINI_API, {"probe_ok": True, "supports_tools": True}, True),
    (Provider.OPENAI_API, {"probe_ok": True, "supports_tools": "true"}, False),
])
def test_model_agentic_requires_real_capability_booleans(
    provider: Provider, metadata: dict[str, object], expected: bool
) -> None:
    assert model_is_agentic(provider, metadata) is expected


class FakeProviderResponse:
    def __init__(self, url: str, body: bytes, *, status: int = 200, headers: dict[str, str] | None = None) -> None:
        self._url = url
        self._body = body
        self.status = status
        self.headers = headers or {}
        self.read_sizes: list[int] = []
        self.closed = False

    def geturl(self) -> str:
        return self._url

    def read(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
        return self._body

    def close(self) -> None:
        self.closed = True


def test_ollama_probe_is_loopback_bounded_and_secret_free() -> None:
    response = FakeProviderResponse(
        OLLAMA_MODELS_URL,
        json.dumps({"models": [{
            "name": "qwen3-coder:latest", "capabilities": ["completion", "tools"],
        }, {"name": "qwen3-coder:latest", "capabilities": ["completion", "tools"]}]}).encode(),
    )
    observed: dict[str, object] = {}

    def opener(request: object, *, timeout: int) -> FakeProviderResponse:
        observed["url"] = request.full_url  # type: ignore[attr-defined]
        observed["authorization"] = request.get_header("Authorization")  # type: ignore[attr-defined]
        observed["timeout"] = timeout
        return response

    result = probe_ollama_models(opener=opener)
    assert result.available is True
    assert result.models == ({
        "id": "qwen3-coder:latest", "installed": True,
        "supports_tools": True, "agentic": True,
    },)
    assert observed == {"url": OLLAMA_MODELS_URL, "authorization": None, "timeout": 5}
    assert response.read_sizes == [MAX_PROVIDER_RESPONSE_BYTES + 1]
    assert response.closed is True
    assert "private" not in repr(result)


def test_ollama_probe_keeps_models_without_tools_non_agentic() -> None:
    response = FakeProviderResponse(
        OLLAMA_MODELS_URL,
        json.dumps({"models": [{"name": "completion-only", "capabilities": ["completion"]}]}).encode(),
    )

    result = probe_ollama_models(opener=lambda *_args, **_kwargs: response)

    assert result.available is True
    assert result.models == ({
        "id": "completion-only", "installed": True,
        "supports_tools": False, "agentic": False,
    },)


def test_huggingface_probe_sends_secret_only_in_private_request_and_gates_capabilities() -> None:
    response = FakeProviderResponse(
        HUGGINGFACE_MODELS_URL,
        json.dumps({"data": [
            {"id": "good/model", "supports_tools": True, "supports_responses": True, "provider_available": True},
            {"id": "text/model", "supports_tools": True, "supports_responses": False, "provider_available": True},
        ]}).encode(),
    )
    observed: dict[str, object] = {}

    def opener(request: object, *, timeout: int) -> FakeProviderResponse:
        observed["url"] = request.full_url  # type: ignore[attr-defined]
        observed["authorization"] = request.get_header("Authorization")  # type: ignore[attr-defined]
        observed["timeout"] = timeout
        return response

    result = probe_huggingface_models("private-token", opener=opener)
    assert result.available is True
    assert result.models[0]["agentic"] is True
    assert result.models[1]["agentic"] is False
    assert observed == {"url": HUGGINGFACE_MODELS_URL, "authorization": "Bearer private-token", "timeout": 5}
    assert "private-token" not in repr(result)


def test_provider_probe_rejects_redirects_and_unbounded_bodies() -> None:
    redirected = FakeProviderResponse("http://localhost:11434/api/tags", b"{}")
    assert probe_ollama_models(opener=lambda *_args, **_kwargs: redirected).error == "redirect_rejected"

    oversized = FakeProviderResponse(OLLAMA_MODELS_URL, b"x" * (MAX_PROVIDER_RESPONSE_BYTES + 1))
    assert probe_ollama_models(opener=lambda *_args, **_kwargs: oversized).error == "provider_response_too_large"


def test_huggingface_probe_requires_a_private_secret_before_network() -> None:
    called = False

    def opener(*_args: object, **_kwargs: object) -> FakeProviderResponse:
        nonlocal called
        called = True
        return FakeProviderResponse(HUGGINGFACE_MODELS_URL, b"{}")

    result = probe_huggingface_models(None, opener=opener)
    assert result.error == "secret_missing"
    assert called is False
