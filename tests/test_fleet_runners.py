from __future__ import annotations

from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from codex_master.fleet_registry import AgentDescriptor, Provider, RunnerKind
from codex_master.fleet_runners import (
    FleetRunnerError,
    build_runner_plan,
    classify_provider_error,
    model_is_agentic,
    parse_gemini_jsonl,
)


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

    assert plan.argv[:4] == ("/usr/local/bin/codex", "--oss", "--local-provider", "ollama")
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
        "/usr/local/bin/gemini", "-p", "-", "--output-format", "stream-json",
        "--model", "gemini-3-flash-preview",
    )
    assert plan.env["GEMINI_CLI_HOME"].endswith("gemini-project-1")
    assert plan.secret_env_name == "GEMINI_API_KEY"
    assert "OPENAI_API_KEY" in plan.unset_env
    assert {"GOOGLE_API_KEY", "GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_CLOUD_PROJECT",
            "GOOGLE_CLOUD_LOCATION", "GOOGLE_GENAI_USE_VERTEXAI"} <= plan.unset_env


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
    ['not json'],
    ['[]'],
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
        Provider.GEMINI_API,
        {"code": 429, "reset_at_utc": "2026-08-03T12:00:00Z"},
        "",
    )
    invalid = classify_provider_error(
        Provider.GEMINI_API,
        {"code": 429, "reset_at_utc": "private reset date"},
        "",
    )
    assert valid.reset_at_utc == "2026-08-03T12:00:00Z"
    assert invalid.reset_at_utc is None


def test_provider_error_rejects_non_rfc3339_structured_reset_time() -> None:
    error = classify_provider_error(
        Provider.GEMINI_API,
        {"code": 429, "reset_at_utc": "2026-08-03T12:00Z"},
        "",
    )
    assert error.reset_at_utc is None


@pytest.mark.parametrize(("provider", "metadata", "expected"), [
    (Provider.OLLAMA_LOCAL, {"installed": True}, True),
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
