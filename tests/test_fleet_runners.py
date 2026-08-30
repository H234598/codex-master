from __future__ import annotations

import io
import json
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from urllib.error import HTTPError, URLError

import pytest

import codex_master.fleet_runners as fleet_runners
from codex_master.fleet_headless import HeadlessJobError, HeadlessProcessResult
from codex_master.fleet_registry import AgentDescriptor, Provider, RunnerKind
from codex_master.fleet_runners import (
    FleetRunnerError,
    GEMINI_DEFAULT_LIGHT_MODEL,
    GEMINI_MODELS_URL,
    MAX_GEMINI_MODELS_RESPONSE_BYTES,
    MAX_GEMINI_MODELS_PAGE_SIZE,
    MAX_GEMINI_PROBE_REQUEST_BYTES,
    MAX_GEMINI_PROBE_RESPONSE_BYTES,
    GEMINI_PROBE_TIMEOUT_SECONDS,
    MAX_HEADLESS_TIMEOUT_SECONDS,
    HUGGINGFACE_MODELS_URL,
    MAX_PROVIDER_RESPONSE_BYTES,
    OLLAMA_MODELS_URL,
    build_runner_plan,
    classify_provider_error,
    ProviderError,
    ProviderErrorQuotaObservation,
    model_is_agentic,
    normalize_gemini_probe_diagnostic_code,
    parse_gemini_jsonl,
    ProbeStdoutEventClass,
    probe_gemini_cli,
    probe_gemini_models,
    probe_gemini_rest,
    probe_huggingface_models,
    probe_ollama_models,
    probe_provider_models,
    validate_gemini_probe_model,
)


def test_probe_provider_models_dispatches_supported_lanes_and_rejects_other(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[object, ...]] = []
    sentinels = {
        Provider.OLLAMA_LOCAL: object(),
        Provider.HUGGINGFACE_INFERENCE: object(),
        Provider.GEMINI_API: object(),
    }
    opener = object()
    monkeypatch.setattr(
        fleet_runners,
        "probe_ollama_models",
        lambda *, opener: calls.append((Provider.OLLAMA_LOCAL, opener))
        or sentinels[Provider.OLLAMA_LOCAL],
    )
    monkeypatch.setattr(
        fleet_runners,
        "probe_huggingface_models",
        lambda secret, *, opener: calls.append(
            (Provider.HUGGINGFACE_INFERENCE, secret, opener)
        )
        or sentinels[Provider.HUGGINGFACE_INFERENCE],
    )
    monkeypatch.setattr(
        fleet_runners,
        "probe_gemini_models",
        lambda secret, *, opener: calls.append((Provider.GEMINI_API, secret, opener))
        or sentinels[Provider.GEMINI_API],
    )

    for provider, sentinel in sentinels.items():
        assert probe_provider_models(provider, secret="secret", opener=opener) is sentinel
    unsupported = probe_provider_models(Provider.OPENAI_API)

    assert calls == [
        (Provider.OLLAMA_LOCAL, opener),
        (Provider.HUGGINGFACE_INFERENCE, "secret", opener),
        (Provider.GEMINI_API, "secret", opener),
    ]
    assert unsupported.provider is Provider.OPENAI_API
    assert unsupported.available is False
    assert unsupported.error == "unsupported_provider"


def test_default_provider_redirect_handler_fails_closed() -> None:
    with pytest.raises(FleetRunnerError, match="redirect_rejected"):
        fleet_runners._RejectRedirectHandler().redirect_request()


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
    assert argv.count("--skip-trust") == 1
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


def test_gemini_provider_probe_timeout_maps_to_provider_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "gemini"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o700)

    timeout_result = HeadlessProcessResult(
        returncode=0,
        stdout=b"",
        stderr=b"",
        stdout_truncated=False,
        stderr_truncated=False,
        timed_out=True,
        cancelled=False,
    )

    captured_timeout: list[float] = []

    def _run_bounded(*_args: object, timeout_seconds: float, **_kwargs: object) -> HeadlessProcessResult:
        captured_timeout.append(timeout_seconds)
        return timeout_result

    monkeypatch.setattr("codex_master.fleet_runners.run_bounded_process", _run_bounded)
    result = probe_gemini_cli("private-gemini-secret", executable)

    assert captured_timeout == [float(GEMINI_PROBE_TIMEOUT_SECONDS)]
    assert GEMINI_PROBE_TIMEOUT_SECONDS == 90
    assert GEMINI_PROBE_TIMEOUT_SECONDS <= MAX_HEADLESS_TIMEOUT_SECONDS
    assert result.ok is False
    assert result.error is not None
    assert result.error.kind == "provider_unavailable"
    assert result.error.retryable is True
    assert result.error.diagnostic_code == "gemini_probe_process_timeout"


@pytest.mark.parametrize(
    (
        "prepare",
        "expected_ok",
        "expected_kind",
        "expected_retryable",
        "expected_code",
        "expected_phase",
        "expected_shape",
        "expected_stdout_shape",
        "expected_stdout_event_class",
        "expected_stdout_error_seen",
    ),
    [
        (
            "timeout_no_output",
            False,
            "provider_unavailable",
            True,
            "gemini_probe_process_timeout",
            "gemini_probe_timeout_no_output",
            "gemini_probe_output_none",
            None,
            None,
            None,
        ),
        (
            "timeout_structured_no_terminal",
            False,
            "provider_unavailable",
            True,
            "gemini_probe_process_timeout",
            "gemini_probe_timeout_structured_no_terminal",
            "gemini_probe_output_stdout_jsonl_incomplete",
            "gemini_probe_stdout_jsonl_incomplete",
            "gemini_probe_stdout_event_error",
            True,
        ),
        (
            "timeout_unknown_type",
            False,
            "provider_unavailable",
            True,
            "gemini_probe_process_timeout",
            "gemini_probe_timeout_structured_no_terminal",
            "gemini_probe_output_stdout_jsonl_incomplete",
            "gemini_probe_stdout_jsonl_incomplete",
            None,
            None,
        ),
        (
            "timeout_unknown_role",
            False,
            "provider_unavailable",
            True,
            "gemini_probe_process_timeout",
            "gemini_probe_timeout_structured_no_terminal",
            "gemini_probe_output_stdout_jsonl_incomplete",
            "gemini_probe_stdout_jsonl_incomplete",
            None,
            None,
        ),
        (
            "timeout_stdout_terminal",
            False,
            "provider_unavailable",
            True,
            "gemini_probe_process_timeout",
            "gemini_probe_timeout_output_unclassified",
            "gemini_probe_output_stdout_terminal",
            "gemini_probe_stdout_terminal_jsonl",
            None,
            None,
        ),
        (
            "timeout_stdout_unclassified",
            False,
            "provider_unavailable",
            True,
            "gemini_probe_process_timeout",
            "gemini_probe_timeout_output_unclassified",
            "gemini_probe_output_stdout_unclassified",
            "gemini_probe_stdout_unclassified",
            None,
            None,
        ),
        (
            "timeout_stderr_only",
            False,
            "provider_unavailable",
            True,
            "gemini_probe_process_timeout",
            "gemini_probe_timeout_output_unclassified",
            "gemini_probe_output_stderr_only",
            None,
            None,
            None,
        ),
        (
            "timeout_stdout_and_stderr",
            False,
            "provider_unavailable",
            True,
            "gemini_probe_process_timeout",
            "gemini_probe_timeout_output_unclassified",
            "gemini_probe_output_stdout_stderr",
            "gemini_probe_stdout_terminal_jsonl",
            None,
            None,
        ),
        (
            "timeout_open_reader",
            False,
            "provider_unavailable",
            True,
            "gemini_probe_process_timeout",
            "gemini_probe_timeout_output_unclassified",
            "gemini_probe_output_truncated_or_pipe_open",
            None,
            None,
            None,
        ),
        (
            "timeout_truncated_or_pipe_open",
            False,
            "provider_unavailable",
            True,
            "gemini_probe_process_timeout",
            "gemini_probe_timeout_structured_no_terminal",
            "gemini_probe_output_truncated_or_pipe_open",
            None,
            None,
            None,
        ),
        (
            "terminal_structured_error",
            False,
            "provider_unavailable",
            True,
            "gemini_probe_structured_response",
            "gemini_probe_normal_exit",
            None,
            None,
            None,
            None,
        ),
        (
            "terminal_result_without_model",
            False,
            "model_unavailable",
            False,
            None,
            "gemini_probe_normal_exit",
            None,
            None,
            None,
            None,
        ),
        (
            "headless_unreaped",
            False,
            "runner_failed",
            False,
            "gemini_probe_runner_failure",
            "gemini_probe_process_group_unreaped",
            None,
            None,
            None,
            None,
        ),
        (
            "normal_exit",
            True,
            None,
            None,
            None,
            "gemini_probe_normal_exit",
            None,
            None,
            None,
            None,
        ),
        (
            "preflight_runner_error",
            False,
            "provider_unavailable",
            False,
            "gemini_probe_runner_failure",
            "gemini_probe_runner_not_started_or_failed",
            None,
            None,
            None,
            None,
        ),
    ],
)
def test_gemini_provider_probe_headless_job_error_maps_to_runner_failure_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    prepare: str,
    expected_ok: bool,
    expected_kind: str | None,
    expected_retryable: bool | None,
    expected_code: str | None,
    expected_phase: str | None,
    expected_shape: str | None,
    expected_stdout_shape: str | None,
    expected_stdout_event_class: ProbeStdoutEventClass | None,
    expected_stdout_error_seen: bool | None,
) -> None:
    executable = tmp_path / "gemini"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o700)

    if prepare == "headless_unreaped":
        def _run_bounded(*_args: object, **_kwargs: object) -> HeadlessProcessResult:
            raise HeadlessJobError("headless_process_unreaped")
        monkeypatch.setattr("codex_master.fleet_runners.run_bounded_process", _run_bounded)
    elif prepare == "normal_exit":
        result_process = HeadlessProcessResult(
            returncode=0,
            stdout=b'{"type":"init","model":"gemini-2.5-flash"}\n{"type":"result"}\n',
            stderr=b"",
            stdout_truncated=False,
            stderr_truncated=False,
            timed_out=False,
            cancelled=False,
        )

        def _run_bounded(*_args: object, **_kwargs: object) -> HeadlessProcessResult:
            return result_process
        monkeypatch.setattr("codex_master.fleet_runners.run_bounded_process", _run_bounded)
    elif prepare == "terminal_structured_error":
        result_process = HeadlessProcessResult(
            returncode=0,
            stdout=(
                b'{"type":"error","error":{"code":503,"status":"UNAVAILABLE","message":"private"}}\n'
                b'{"type":"result"}\n'
            ),
            stderr=b"",
            stdout_truncated=False,
            stderr_truncated=False,
            timed_out=False,
            cancelled=False,
        )

        def _run_bounded(*_args: object, **_kwargs: object) -> HeadlessProcessResult:
            return result_process
        monkeypatch.setattr("codex_master.fleet_runners.run_bounded_process", _run_bounded)
    elif prepare == "terminal_result_without_model":
        result_process = HeadlessProcessResult(
            returncode=0,
            stdout=b'{"type":"result"}\n',
            stderr=b"",
            stdout_truncated=False,
            stderr_truncated=False,
            timed_out=False,
            cancelled=False,
        )

        def _run_bounded(*_args: object, **_kwargs: object) -> HeadlessProcessResult:
            return result_process
        monkeypatch.setattr("codex_master.fleet_runners.run_bounded_process", _run_bounded)
    elif prepare in {
        "timeout_no_output",
        "timeout_structured_no_terminal",
        "timeout_unknown_type",
        "timeout_unknown_role",
    }:
        if prepare == "timeout_no_output":
            stdout = b""
        elif prepare == "timeout_unknown_type":
            stdout = b'{"type":"unknown_event"}\n'
        elif prepare == "timeout_unknown_role":
            stdout = b'{"type":"message","role":"system","content":"hello"}\n'
        else:
            stdout = b'{"type":"error","error":{"code":503,"status":"UNAVAILABLE","message":"service unavailable"}}\n'
        stderr = b""
        timeout_result = HeadlessProcessResult(
            returncode=0,
            stdout=stdout,
            stderr=stderr,
            stdout_truncated=False,
            stderr_truncated=False,
            timed_out=True,
            cancelled=False,
        )

        def _run_bounded(*_args: object, **_kwargs: object) -> HeadlessProcessResult:
            return timeout_result
        monkeypatch.setattr("codex_master.fleet_runners.run_bounded_process", _run_bounded)
    elif prepare == "timeout_stdout_terminal":
        timeout_result = HeadlessProcessResult(
            returncode=0,
            stdout=(
                b'{"type":"init","model":"gemini-2.5-flash"}\n'
                b'{"type":"result"}\n'
            ),
            stderr=b"",
            stdout_truncated=False,
            stderr_truncated=False,
            timed_out=True,
            cancelled=False,
        )

        def _run_bounded(*_args: object, **_kwargs: object) -> HeadlessProcessResult:
            return timeout_result
        monkeypatch.setattr("codex_master.fleet_runners.run_bounded_process", _run_bounded)
    elif prepare == "timeout_stdout_unclassified":
        timeout_result = HeadlessProcessResult(
            returncode=0,
            stdout=b"not-json\n",
            stderr=b"",
            stdout_truncated=False,
            stderr_truncated=False,
            timed_out=True,
            cancelled=False,
        )

        def _run_bounded(*_args: object, **_kwargs: object) -> HeadlessProcessResult:
            return timeout_result
        monkeypatch.setattr("codex_master.fleet_runners.run_bounded_process", _run_bounded)
    elif prepare in {"timeout_stderr_only", "timeout_stdout_and_stderr"}:
        timeout_result = HeadlessProcessResult(
            returncode=0,
            stdout=(
                b""
                if prepare == "timeout_stderr_only"
                else (
                    b'{"type":"init","model":"gemini-2.5-flash"}\n'
                    b'{"type":"result"}\n'
                )
            ),
                stderr=b"timeout stderr\n",
                stdout_truncated=False,
                stderr_truncated=False,
                timed_out=True,
                cancelled=False,
            )

        def _run_bounded(*_args: object, **_kwargs: object) -> HeadlessProcessResult:
            return timeout_result
        monkeypatch.setattr("codex_master.fleet_runners.run_bounded_process", _run_bounded)
    elif prepare == "timeout_open_reader":
        timeout_result = HeadlessProcessResult(
            returncode=0,
            stdout=(
                b'{"type":"init","model":"gemini-2.5-flash"}\n'
                b'{"type":"result"}\n'
            ),
            stderr=b"",
            stdout_truncated=False,
            stderr_truncated=False,
            timed_out=True,
            cancelled=False,
            readers_alive=True,
        )

        def _run_bounded(*_args: object, **_kwargs: object) -> HeadlessProcessResult:
            return timeout_result
        monkeypatch.setattr("codex_master.fleet_runners.run_bounded_process", _run_bounded)
    elif prepare == "timeout_truncated_or_pipe_open":
        timeout_result = HeadlessProcessResult(
            returncode=0,
            stdout=b'{"type":"init"}\n',
            stderr=b"",
            stdout_truncated=True,
            stderr_truncated=False,
            timed_out=True,
            cancelled=False,
        )

        def _run_bounded(*_args: object, **_kwargs: object) -> HeadlessProcessResult:
            return timeout_result
        monkeypatch.setattr("codex_master.fleet_runners.run_bounded_process", _run_bounded)
    else:
        executable.write_text("not executable", encoding="utf-8")
        executable.chmod(0o600)

    result = probe_gemini_cli("private-gemini-secret", executable)

    assert result.ok is expected_ok
    assert result.process_phase == expected_phase
    if expected_ok:
        assert result.error is None
    else:
        assert result.error is not None
        assert result.error.kind == expected_kind
        assert result.error.retryable is expected_retryable
        assert result.error.diagnostic_code == expected_code
    assert result.process_output_shape == expected_shape
    assert result.process_stdout_shape == expected_stdout_shape
    assert result.process_stdout_event_class == expected_stdout_event_class
    assert result.process_stdout_error_seen == expected_stdout_error_seen


@pytest.mark.parametrize(("stdout", "expected_code", "expected_kind", "expected_retryable"), [
    (
        b'{"type":"error","error":{"code":503,"status":"UNAVAILABLE","message":"private"}}\n'
        b'{"type":"result"}\n',
        "gemini_probe_structured_response",
        "provider_unavailable",
        True,
    ),
    (
        b'{"type":"init","model":"gemini-2.5-flash"}\n',
        "gemini_probe_jsonl_terminal_invalid",
        "runner_failed",
        False,
    ),
    (
        b"not-json\n",
        "gemini_probe_jsonl_terminal_invalid",
        "runner_failed",
        False,
    ),
])
def test_gemini_provider_probe_reports_structured_and_parser_diagnostic_codes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stdout: bytes,
    expected_code: str,
    expected_kind: str,
    expected_retryable: bool,
) -> None:
    executable = tmp_path / "gemini"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o700)

    result_process = HeadlessProcessResult(
        returncode=0,
        stdout=stdout,
        stderr=b"",
        stdout_truncated=False,
        stderr_truncated=False,
        timed_out=False,
        cancelled=False,
    )

    def _run_bounded(*_args: object, **_kwargs: object) -> HeadlessProcessResult:
        return result_process

    monkeypatch.setattr("codex_master.fleet_runners.run_bounded_process", _run_bounded)
    result = probe_gemini_cli("private-gemini-secret", executable)

    assert result.ok is False
    assert result.error is not None
    assert result.error.kind == expected_kind
    assert result.error.retryable is expected_retryable
    assert result.error.diagnostic_code == expected_code
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


def test_provider_error_records_quota_retry_scope_model_and_clamps_duration() -> None:
    model_payload = {
        "error": {
            "code": 429,
            "status": "RESOURCE_EXHAUSTED",
            "details": [
                {
                    "@type": "type.googleapis.com/google.rpc.QuotaFailure",
                    "violations": [
                        {
                            "quotaDimensions": {
                                "model": "gemini",
                                "region": "us-central1",
                                "feature": "batch",
                            },
                        },
                    ],
                },
                {
                    "@type": "type.googleapis.com/google.rpc.RetryInfo",
                    "retryDelay": "1.1s",
                },
            ],
        },
    }
    bounded_payload = {
        "error": {
            "code": 429,
            "status": "RESOURCE_EXHAUSTED",
            "details": [
                {
                    "@type": "type.googleapis.com/google.rpc.QuotaFailure",
                    "violations": [
                        {
                            "quotaDimensions": {"model": "gemini"},
                        },
                    ],
                },
                {
                    "@type": "type.googleapis.com/google.rpc.RetryInfo",
                    "retryDelay": "3600.1s",
                },
            ],
        },
    }
    error = classify_provider_error(Provider.GEMINI_API, model_payload, "")
    bounded_error = classify_provider_error(Provider.GEMINI_API, bounded_payload, "")

    assert error.kind == "account_limited"
    assert error.status_code == 429
    assert error.reset_at_utc is None
    assert error.quota_observation is not None
    assert error.quota_observation.scope == "model"
    assert error.quota_observation.retry_after_seconds == 2
    assert "retryDelay" not in repr(error.quota_observation)
    assert "gemini" not in repr(error.quota_observation)
    assert "us-central1" not in repr(error.quota_observation)
    assert "batch" not in repr(error.quota_observation)
    assert error.quota_observation == ProviderErrorQuotaObservation("model", 2)
    assert bounded_error.kind == "account_limited"
    assert bounded_error.status_code == 429
    assert bounded_error.quota_observation is not None
    assert bounded_error.quota_observation.scope == "model"
    assert bounded_error.quota_observation.retry_after_seconds == 3600
    assert "retryDelay" not in repr(bounded_error.quota_observation)
    assert "3600.1" not in repr(bounded_error.quota_observation)


def test_provider_error_records_scope_account_unknown_and_sanitizes_retry_info() -> None:
    account_payload = {
        "error": {
            "code": 429,
            "status": "RESOURCE_EXHAUSTED",
            "details": [
                {
                    "@type": "type.googleapis.com/google.rpc.QuotaFailure",
                    "violations": [
                        {
                            "quotaDimensions": {},
                        },
                    ],
                },
                {
                    "@type": "type.googleapis.com/google.rpc.RetryInfo",
                    "retryDelay": "0s",
                },
            ],
        },
    }
    unknown_payload = {
        "error": {
            "code": 429,
            "status": "RESOURCE_EXHAUSTED",
            "details": [
                {
                    "@type": "type.googleapis.com/google.rpc.QuotaFailure",
                    "violations": [{"quotaDimensions": {"region": "us"}}],
                },
                {
                    "@type": "type.googleapis.com/google.rpc.QuotaFailure",
                    "violations": [{"quotaDimensions": {"model": "gemini"}}],
                },
                {
                    "@type": "type.googleapis.com/google.rpc.RetryInfo",
                    "retryDelay": "1.5s",
                },
                {
                    "@type": "type.googleapis.com/google.rpc.RetryInfo",
                    "retryDelay": "2.5s",
                },
            ],
        },
    }
    malformed_retry_payload = {
        "error": {
            "code": 429,
            "status": "RESOURCE_EXHAUSTED",
            "details": [
                {
                    "@type": "type.googleapis.com/google.rpc.QuotaFailure",
                    "violations": [{"quotaDimensions": {"model": "gemini"}}],
                },
                {
                    "@type": "type.googleapis.com/google.rpc.RetryInfo",
                    "retryDelay": "not-a-duration",
                },
            ],
        },
    }
    overlong_retry_payload = {
        "error": {
            "code": 429,
            "status": "RESOURCE_EXHAUSTED",
            "details": [
                {
                    "@type": "type.googleapis.com/google.rpc.QuotaFailure",
                    "violations": [{"quotaDimensions": {}}],
                },
                {
                    "@type": "type.googleapis.com/google.rpc.RetryInfo",
                    "retryDelay": "9" * 500 + "s",
                },
            ],
        },
    }
    missing_payload = {"error": {"code": 429, "status": "RESOURCE_EXHAUSTED", "details": [{"foo": 1}]}}

    account_error = classify_provider_error(Provider.GEMINI_API, account_payload, "")
    unknown_error = classify_provider_error(Provider.GEMINI_API, unknown_payload, "")
    malformed_retry_error = classify_provider_error(Provider.GEMINI_API, malformed_retry_payload, "")
    overlong_retry_error = classify_provider_error(Provider.GEMINI_API, overlong_retry_payload, "")
    missing_payload_error = classify_provider_error(Provider.GEMINI_API, missing_payload, "")

    assert account_error.kind == "account_limited"
    assert account_error.status_code == 429
    assert account_error.quota_observation is not None
    assert account_error.quota_observation.scope == "account"
    assert account_error.quota_observation.retry_after_seconds is None
    assert unknown_error.quota_observation is not None
    assert unknown_error.quota_observation.scope == "unknown"
    assert unknown_error.quota_observation.retry_after_seconds is None
    assert malformed_retry_error.quota_observation is not None
    assert malformed_retry_error.quota_observation.scope == "model"
    assert malformed_retry_error.quota_observation.retry_after_seconds is None
    assert overlong_retry_error.quota_observation is not None
    assert overlong_retry_error.quota_observation.scope == "account"
    assert overlong_retry_error.quota_observation.retry_after_seconds is None
    assert missing_payload_error.quota_observation is not None
    assert missing_payload_error.quota_observation.scope == "unknown"
    assert missing_payload_error.quota_observation.retry_after_seconds is None


def test_provider_error_non_429_keeps_quota_observation_none_and_old_constructors() -> None:
    not_429 = classify_provider_error(
        Provider.GEMINI_API, {"code": 503, "status": "UNAVAILABLE", "details": []}, "",
    )
    no_http_429 = classify_provider_error(
        Provider.GEMINI_API, {"status": "RESOURCE_EXHAUSTED", "details": []}, "",
    )
    legacy = ProviderError("account_limited", True, 429, None)

    assert not_429.kind == "provider_unavailable"
    assert not_429.quota_observation is None
    assert no_http_429.kind == "account_limited"
    assert no_http_429.quota_observation is None
    assert legacy == ProviderError("account_limited", True, 429, None)


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


def _gemini_models_response(
    *,
    model: str = GEMINI_DEFAULT_LIGHT_MODEL,
    methods: list[str] | None = None,
    include_model: bool = True,
) -> FakeProviderResponse:
    url = f"{GEMINI_MODELS_URL}?pageSize={MAX_GEMINI_MODELS_PAGE_SIZE}"
    models = []
    if include_model:
        models.append({
            "name": f"models/{model}",
            "supportedGenerationMethods": methods if methods is not None else ["generateContent"],
        })
    return FakeProviderResponse(url, json.dumps({"models": models}).encode())


@pytest.mark.parametrize(("include_model", "methods", "expected_code"), [
    (False, None, "gemini_probe_generate_content_capability_model_missing"),
    (True, ["countTokens"], "gemini_probe_generate_content_capability_method_missing"),
])
def test_gemini_rest_probe_stops_before_content_without_exact_capability(
    include_model: bool,
    methods: list[str] | None,
    expected_code: str,
) -> None:
    model_response = _gemini_models_response(include_model=include_model, methods=methods)
    observed_urls: list[str] = []

    def opener(request: object, *, timeout: int) -> FakeProviderResponse:
        observed_urls.append(request.full_url)  # type: ignore[attr-defined]
        if len(observed_urls) > 1:
            pytest.fail("content request occurred without generateContent capability")
        return model_response

    result = probe_gemini_rest("private-gemini-key", opener=opener)

    assert observed_urls == [model_response.geturl()]
    assert result.ok is False
    assert result.model == GEMINI_DEFAULT_LIGHT_MODEL
    assert result.error is not None
    assert result.error.kind == "model_unavailable"
    assert result.error.diagnostic_code == expected_code
    assert getattr(result, "endpoint_role", None) == "generate_content"
    assert getattr(result, "http_class", "unexpected") is None


def test_gemini_rest_probe_uses_capability_checked_generate_content_contract() -> None:
    model_response = _gemini_models_response()
    content_url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        "gemini-3.1-flash-lite:generateContent"
    )
    content_response = FakeProviderResponse(
        content_url,
        json.dumps({"candidates": [{"finishReason": "MAX_TOKENS"}]}).encode(),
    )
    responses = iter([model_response, content_response])
    observed: list[dict[str, object]] = []

    def opener(request: object, *, timeout: int) -> FakeProviderResponse:
        observed.append({
            "url": request.full_url,  # type: ignore[attr-defined]
            "method": request.get_method(),  # type: ignore[attr-defined]
            "key": request.get_header("X-goog-api-key"),  # type: ignore[attr-defined]
            "authorization": request.get_header("Authorization"),  # type: ignore[attr-defined]
            "content_type": request.get_header("Content-type"),  # type: ignore[attr-defined]
            "body": request.data,  # type: ignore[attr-defined]
            "timeout": timeout,
        })
        return next(responses)

    result = probe_gemini_rest("private-gemini-key", opener=opener)

    assert result.ok is True
    assert result.model == GEMINI_DEFAULT_LIGHT_MODEL
    assert result.supports_tools is True
    assert result.error is None
    assert getattr(result, "endpoint_role", None) == "generate_content"
    assert getattr(result, "http_class", None) == "2xx"
    assert observed == [
        {
            "url": model_response.geturl(),
            "method": "GET",
            "key": "private-gemini-key",
            "authorization": None,
            "content_type": None,
            "body": None,
            "timeout": 5,
        },
        {
            "url": content_url,
            "method": "POST",
            "key": "private-gemini-key",
            "authorization": None,
            "content_type": "application/json",
            "body": json.dumps({
                "contents": [{"role": "user", "parts": [{"text": "ping"}]}],
                "generationConfig": {"maxOutputTokens": 1},
            }, separators=(",", ":"), sort_keys=True).encode(),
            "timeout": 5,
        },
    ]
    assert len(observed[1]["body"]) <= MAX_GEMINI_PROBE_REQUEST_BYTES  # type: ignore[arg-type]
    assert b"private-gemini-key" not in observed[1]["body"]  # type: ignore[operator]
    assert model_response.closed is True
    assert content_response.read_sizes == [MAX_GEMINI_PROBE_RESPONSE_BYTES + 1]
    assert content_response.closed is True
    assert "private-gemini-key" not in repr(result)
    assert content_url not in repr(result)


@pytest.mark.parametrize(("status", "provider_fields", "expected_kind", "retryable", "expected_code"), [
    (400, {"code": "invalid_request"}, "runner_failed", False,
     "gemini_probe_generate_content_http_4xx_contract_rejected"),
    (400, {"code": "parameter_unknown"}, "runner_failed", False,
     "gemini_probe_generate_content_http_4xx_contract_rejected"),
    (400, {"status": "INVALID_ARGUMENT"}, "runner_failed", False,
     "gemini_probe_generate_content_http_4xx_contract_rejected"),
    (401, {"code": "authentication"}, "auth_invalid", False,
     "gemini_probe_generate_content_http_4xx_authentication"),
    (401, {"status": "UNAUTHENTICATED"}, "auth_invalid", False,
     "gemini_probe_generate_content_http_4xx_authentication"),
    (403, {"code": "permission_denied"}, "auth_or_billing_denied", False,
     "gemini_probe_generate_content_http_4xx_auth_or_billing_denied"),
    (403, {"status": "PERMISSION_DENIED"}, "auth_or_billing_denied", False,
     "gemini_probe_generate_content_http_4xx_auth_or_billing_denied"),
    (404, {"code": "model_not_found"}, "model_unavailable", False,
     "gemini_probe_generate_content_http_4xx_model_not_found"),
    (404, {"status": "MODEL_NOT_FOUND"}, "model_unavailable", False,
     "gemini_probe_generate_content_http_4xx_model_not_found"),
    (404, {"code": "not_found"}, "runner_failed", False,
     "gemini_probe_generate_content_http_4xx_not_found_unclassified"),
    (404, {"status": "NOT_FOUND"}, "runner_failed", False,
     "gemini_probe_generate_content_http_4xx_not_found_unclassified"),
    (429, {"code": "rate_limit_exceeded"}, "account_limited", True,
     "gemini_probe_generate_content_http_4xx_rate_or_quota_exhausted"),
    (429, {"code": "quota_exceeded"}, "account_limited", True,
     "gemini_probe_generate_content_http_4xx_rate_or_quota_exhausted"),
    (429, {"status": "RESOURCE_EXHAUSTED"}, "account_limited", True,
     "gemini_probe_generate_content_http_4xx_rate_or_quota_exhausted"),
    (500, {"code": "api_error"}, "provider_unavailable", True,
     "gemini_probe_generate_content_http_5xx_provider_unavailable"),
    (503, {"code": "service_unavailable"}, "provider_unavailable", True,
     "gemini_probe_generate_content_http_5xx_provider_unavailable"),
    (503, {"status": "UNAVAILABLE"}, "provider_unavailable", True,
     "gemini_probe_generate_content_http_5xx_provider_unavailable"),
    (418, {"code": "vendor-private-project-marker"}, "runner_failed", False,
     "gemini_probe_generate_content_http_4xx_client_rejected_unknown"),
])
def test_gemini_rest_probe_classifies_only_allowlisted_redacted_error_semantics(
    status: int,
    provider_fields: dict[str, object],
    expected_kind: str,
    retryable: bool,
    expected_code: str,
) -> None:
    model_response = _gemini_models_response()
    content_url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        "gemini-3.1-flash-lite:generateContent"
    )
    body_marker = f"private-provider-message-{status}"
    header_marker = f"private-provider-header-{status}"
    project_marker = f"private-project-{status}"
    error_body = json.dumps({
        "error": {
            **provider_fields,
            "message": body_marker,
            "project": project_marker,
        },
    }).encode()
    content_response = FakeProviderResponse(
        content_url,
        error_body,
        status=status,
        headers={"X-Private-Diagnostic": header_marker},
    )
    failure = HTTPError(content_url, status, "private-http-reason", None, content_response)
    responses: list[object] = [model_response, failure]

    def opener(*_args: object, **_kwargs: object) -> FakeProviderResponse:
        response = responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    result = probe_gemini_rest("private-gemini-key", opener=opener)

    assert result.ok is False
    assert result.model == GEMINI_DEFAULT_LIGHT_MODEL
    assert result.error is not None
    assert result.error.kind == expected_kind
    assert result.error.retryable is retryable
    assert result.error.status_code is None
    assert result.error.diagnostic_code == expected_code
    assert getattr(result, "endpoint_role", None) == "generate_content"
    assert getattr(result, "http_class", None) == ("5xx" if status >= 500 else "4xx")
    rendered = repr(result)
    for marker in (
        body_marker,
        header_marker,
        project_marker,
        "vendor-private-project-marker",
        "private-http-reason",
        "private-gemini-key",
        content_url,
    ):
        assert marker not in rendered
    assert model_response.closed is True
    assert content_response.closed is True


@pytest.mark.parametrize("provider_fields", [
    {"code": "not_found"},
    {"status": "NOT_FOUND"},
])
def test_gemini_rest_probe_classifies_direct_not_found_response_neutrally(
    provider_fields: dict[str, str],
) -> None:
    model_response = _gemini_models_response()
    content_url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        "gemini-3.1-flash-lite:generateContent"
    )
    content_response = FakeProviderResponse(
        content_url,
        json.dumps({"error": provider_fields}).encode(),
        status=404,
    )
    responses = iter([model_response, content_response])

    result = probe_gemini_rest(
        "private-gemini-key",
        opener=lambda *_args, **_kwargs: next(responses),
    )

    assert result.ok is False
    assert result.error is not None
    assert result.error.kind == "runner_failed"
    assert result.error.retryable is False
    assert result.error.diagnostic_code == (
        "gemini_probe_generate_content_http_4xx_not_found_unclassified"
    )
    assert result.error.quota_observation is None
    assert result.http_class == "4xx"


def test_gemini_rest_probe_preserves_redacted_quota_scope_and_retry() -> None:
    model_response = _gemini_models_response()
    content_url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        "gemini-3.1-flash-lite:generateContent"
    )
    content_response = FakeProviderResponse(
        content_url,
        json.dumps({
            "error": {
                "code": "quota_exceeded",
                "message": "private quota body",
                "details": [
                    {
                        "@type": "type.googleapis.com/google.rpc.QuotaFailure",
                        "violations": [{"quotaDimensions": {"model": "private-model-value"}}],
                    },
                    {
                        "@type": "type.googleapis.com/google.rpc.RetryInfo",
                        "retryDelay": "7s",
                    },
                ],
            },
        }).encode(),
        status=429,
    )
    failure = HTTPError(content_url, 429, "private", None, content_response)
    responses: list[object] = [model_response, failure]

    def opener(*_args: object, **_kwargs: object) -> FakeProviderResponse:
        response = responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    result = probe_gemini_rest("private-gemini-key", opener=opener)

    assert result.error is not None
    assert result.error.kind == "account_limited"
    assert result.error.quota_observation == ProviderErrorQuotaObservation("model", 7)
    assert "private quota body" not in repr(result)
    assert "private-model-value" not in repr(result)


@pytest.mark.parametrize("body", [
    b"{",
    b"[]",
    b"{}",
    b"{}" + b"x" * MAX_GEMINI_PROBE_RESPONSE_BYTES,
])
def test_gemini_rest_probe_rejects_invalid_generate_content_json_without_leak(body: bytes) -> None:
    model_response = _gemini_models_response()
    content_url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        "gemini-3.1-flash-lite:generateContent"
    )
    content_response = FakeProviderResponse(content_url, body)
    responses = iter([model_response, content_response])

    result = probe_gemini_rest(
        "private-gemini-key",
        opener=lambda *_args, **_kwargs: next(responses),
    )

    assert result.ok is False
    assert result.error is not None
    assert result.error.kind == "provider_unavailable"
    assert result.error.diagnostic_code == "gemini_probe_generate_content_http_2xx_json_invalid"
    assert getattr(result, "endpoint_role", None) == "generate_content"
    assert getattr(result, "http_class", None) == "2xx"
    assert body.decode("utf-8", errors="ignore") not in repr(result)
    assert content_url not in repr(result)


@pytest.mark.parametrize("value", [
    "gemini_probe_generate_content_capability_model_missing",
    "gemini_probe_generate_content_capability_method_missing",
    "gemini_probe_generate_content_http_4xx_contract_rejected",
    "gemini_probe_generate_content_http_4xx_authentication",
    "gemini_probe_generate_content_http_4xx_auth_or_billing_denied",
    "gemini_probe_generate_content_http_4xx_model_not_found",
    "gemini_probe_generate_content_http_4xx_not_found_unclassified",
    "gemini_probe_generate_content_http_4xx_rate_or_quota_exhausted",
    "gemini_probe_generate_content_http_4xx_client_rejected_unknown",
    "gemini_probe_generate_content_http_5xx_provider_unavailable",
    "gemini_probe_generate_content_http_2xx_json_invalid",
    "gemini_probe_generate_content_redirect_rejected",
    "gemini_probe_generate_content_transport",
])
def test_gemini_probe_normalizer_accepts_only_generate_content_probe_diagnostics(value: str) -> None:
    assert normalize_gemini_probe_diagnostic_code(value) == value


@pytest.mark.parametrize("retired", [
    "gemini_probe_rest_http_unclassified",
    "gemini_probe_rest_interactions_http_4xx",
    "gemini_probe_rest_interactions_http_5xx",
    "gemini_probe_rest_interaction_not_completed",
    "gemini_probe_rest_steps_invalid",
    "gemini_probe_rest_model_output_missing",
    "gemini_probe_generate_content_http_4xx_route_not_found",
])
def test_gemini_probe_normalizer_rejects_retired_diagnostics(retired: str) -> None:
    assert normalize_gemini_probe_diagnostic_code(retired) is None


def test_gemini_rest_probe_maps_generate_content_transport_without_leak() -> None:
    model_response = _gemini_models_response()
    responses: list[object] = [model_response, URLError("private-offline-marker")]

    def opener(*_args: object, **_kwargs: object) -> FakeProviderResponse:
        response = responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    result = probe_gemini_rest("private-gemini-key", opener=opener)

    assert result.ok is False
    assert result.model == GEMINI_DEFAULT_LIGHT_MODEL
    assert result.error is not None
    assert result.error.kind == "provider_unavailable"
    assert result.error.diagnostic_code == "gemini_probe_generate_content_transport"
    assert getattr(result, "endpoint_role", None) == "generate_content"
    assert getattr(result, "http_class", None) == "transport"
    assert "private-offline-marker" not in repr(result)


@pytest.mark.parametrize("model", [
    "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-lite:generateContent",
    "gemini-2.5-flash-lite/extra",
    "gemini-2.5-flash-lite?x=1",
    "GEMINI-2.5-FLASH-LITE",
    " gemini-2.5-flash-lite",
])
def test_gemini_rest_probe_rejects_noncanonical_model_without_opener(model: str) -> None:
    result = probe_gemini_rest(
        "private-gemini-key",
        model=model,
        opener=lambda *_args, **_kwargs: pytest.fail("invalid model reached opener"),
    )

    assert result.model is None
    assert result.error is not None
    assert result.error.kind == "model_unavailable"


def test_gemini_models_catalog_is_paged_bounded_and_projects_safe_fields() -> None:
    secret = "private-gemini-key"
    future_model = "gemini-9.9-future-preview"
    first_url = f"{GEMINI_MODELS_URL}?pageSize={MAX_GEMINI_MODELS_PAGE_SIZE}"
    second_url = f"{first_url}&pageToken=next%2Ftoken"
    first_response = FakeProviderResponse(
        first_url,
        json.dumps({
            "models": [
                {
                    "name": "models/gemini-2.5-flash-lite",
                    "supportedGenerationMethods": ["countTokens", "generateContent", "privateMethod"],
                },
                {
                    "name": f"models/{future_model}",
                    "supportedGenerationMethods": ["countTokens"],
                },
            ],
            "nextPageToken": "next/token",
        }).encode(),
    )
    second_response = FakeProviderResponse(
        second_url,
        json.dumps({
            "models": [{
                "name": "models/gemini-2.5-flash-lite",
                "supportedGenerationMethods": ["streamGenerateContent"],
            }],
        }).encode(),
    )
    responses = iter([first_response, second_response])
    observed: list[dict[str, object]] = []

    def opener(request: object, *, timeout: int) -> FakeProviderResponse:
        observed.append({
            "url": request.full_url,  # type: ignore[attr-defined]
            "key": request.get_header("X-goog-api-key"),  # type: ignore[attr-defined]
            "authorization": request.get_header("Authorization"),  # type: ignore[attr-defined]
            "timeout": timeout,
        })
        return next(responses)

    result = probe_gemini_models(secret, opener=opener)

    assert result.available is True
    assert result.models == (
        {
            "id": "gemini-2.5-flash-lite",
            "supported_generation_methods": ["countTokens", "generateContent", "streamGenerateContent"],
            "supports_generate_content": True,
            "agentic": True,
            "readiness_worker": True,
        },
        {
            "id": future_model,
            "supported_generation_methods": ["countTokens"],
            "supports_generate_content": False,
            "agentic": False,
            "readiness_worker": False,
        },
    )
    assert observed == [
        {"url": first_url, "key": secret, "authorization": None, "timeout": 5},
        {"url": second_url, "key": secret, "authorization": None, "timeout": 5},
    ]
    assert all(secret not in str(item["url"]) for item in observed)
    assert all(secret not in str(item) for item in result.models)
    assert first_response.read_sizes == [MAX_GEMINI_MODELS_RESPONSE_BYTES + 1]
    assert second_response.read_sizes == [MAX_GEMINI_MODELS_RESPONSE_BYTES + 1]


@pytest.mark.parametrize(("status", "provider_fields", "expected_error"), [
    (400, {"code": "invalid_request"}, "runner_failed"),
    (403, {"code": "permission_denied"}, "auth_or_billing_denied"),
    (404, {"code": "model_not_found"}, "model_unavailable"),
    (429, {"code": "quota_exceeded"}, "account_limited"),
    (503, {"code": "service_unavailable"}, "provider_unavailable"),
])
def test_gemini_models_uses_shared_redacted_http_error_normalization(
    status: int,
    provider_fields: dict[str, object],
    expected_error: str,
) -> None:
    url = f"{GEMINI_MODELS_URL}?pageSize={MAX_GEMINI_MODELS_PAGE_SIZE}"
    body_marker = f"private-models-body-{status}"
    response = FakeProviderResponse(
        url,
        json.dumps({"error": {**provider_fields, "message": body_marker}}).encode(),
        status=status,
    )
    failure = HTTPError(url, status, "private-models-reason", None, response)

    result = probe_gemini_models(
        "private-gemini-key",
        opener=lambda *_args, **_kwargs: (_ for _ in ()).throw(failure),
    )

    assert result.available is False
    assert result.models == ()
    assert result.error == expected_error
    assert body_marker not in repr(result)
    assert "private-models-reason" not in repr(result)
    assert "private-gemini-key" not in repr(result)
    assert response.closed is True


def test_gemini_rest_probe_preserves_models_list_normalized_error() -> None:
    url = f"{GEMINI_MODELS_URL}?pageSize={MAX_GEMINI_MODELS_PAGE_SIZE}"
    response = FakeProviderResponse(
        url,
        json.dumps({
            "error": {
                "code": "permission_denied",
                "message": "private-models-permission-body",
            },
        }).encode(),
        status=403,
    )
    failure = HTTPError(url, 403, "private-models-permission-reason", None, response)

    result = probe_gemini_rest(
        "private-gemini-key",
        opener=lambda *_args, **_kwargs: (_ for _ in ()).throw(failure),
    )

    assert result.ok is False
    assert result.error is not None
    assert result.error.kind == "auth_or_billing_denied"
    assert result.error.retryable is False
    assert result.error.status_code is None
    assert result.error.diagnostic_code == "gemini_probe_generate_content_http_4xx_auth_or_billing_denied"
    assert result.endpoint_role == "generate_content"
    assert result.http_class == "4xx"
    assert "private-models-permission" not in repr(result)
    assert "private-gemini-key" not in repr(result)


def test_gemini_rest_probe_preserves_direct_models_http_diagnostic() -> None:
    url = f"{GEMINI_MODELS_URL}?pageSize={MAX_GEMINI_MODELS_PAGE_SIZE}"
    response = FakeProviderResponse(
        url,
        json.dumps({
            "error": {
                "code": "invalid_request",
                "message": "private-direct-models-body",
            },
        }).encode(),
        status=400,
    )

    result = probe_gemini_rest("private-gemini-key", opener=lambda *_args, **_kwargs: response)

    assert result.ok is False
    assert result.error is not None
    assert result.error.kind == "runner_failed"
    assert result.error.retryable is False
    assert result.error.diagnostic_code == "gemini_probe_generate_content_http_4xx_contract_rejected"
    assert result.http_class == "4xx"
    assert "private-direct-models-body" not in repr(result)
    assert "private-gemini-key" not in repr(result)


def test_gemini_rest_probe_preserves_models_list_model_quota_observation() -> None:
    url = f"{GEMINI_MODELS_URL}?pageSize={MAX_GEMINI_MODELS_PAGE_SIZE}"
    response = FakeProviderResponse(
        url,
        json.dumps({
            "error": {
                "code": "quota_exceeded",
                "message": "private-models-quota-body",
                "details": [
                    {
                        "@type": "type.googleapis.com/google.rpc.QuotaFailure",
                        "violations": [{"quotaDimensions": {"model": "private-model-value"}}],
                    },
                    {
                        "@type": "type.googleapis.com/google.rpc.RetryInfo",
                        "retryDelay": "11s",
                    },
                ],
            },
        }).encode(),
        status=429,
    )

    result = probe_gemini_rest("private-gemini-key", opener=lambda *_args, **_kwargs: response)

    assert result.ok is False
    assert result.model == GEMINI_DEFAULT_LIGHT_MODEL
    assert result.error is not None
    assert result.error.kind == "account_limited"
    assert result.error.retryable is True
    assert result.error.quota_observation == ProviderErrorQuotaObservation("model", 11)
    assert result.error.diagnostic_code == "gemini_probe_generate_content_http_4xx_rate_or_quota_exhausted"
    assert result.http_class == "4xx"
    assert "private-models-quota-body" not in repr(result)
    assert "private-model-value" not in repr(result)


def test_gemini_rest_probe_rejects_direct_models_redirect_before_body_parse() -> None:
    url = f"{GEMINI_MODELS_URL}?pageSize={MAX_GEMINI_MODELS_PAGE_SIZE}"
    response = FakeProviderResponse(url, b"private-redirect-body", status=302)

    result = probe_gemini_rest("private-gemini-key", opener=lambda *_args, **_kwargs: response)

    assert result.ok is False
    assert result.error is not None
    assert result.error.kind == "provider_unavailable"
    assert result.error.retryable is True
    assert result.error.diagnostic_code == "gemini_probe_generate_content_redirect_rejected"
    assert result.http_class == "transport"
    assert response.read_sizes == []
    assert response.closed is True
    assert "private-redirect-body" not in repr(result)


def test_gemini_rest_probe_uses_valid_custom_model_after_capability_check() -> None:
    model = "gemini-2.5-flash-lite"
    model_response = _gemini_models_response(model=model)
    content_url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        "gemini-2.5-flash-lite:generateContent"
    )
    content_response = FakeProviderResponse(
        content_url,
        json.dumps({"candidates": [{"finishReason": "MAX_TOKENS"}]}).encode(),
    )
    responses = iter([model_response, content_response])
    observed_urls: list[str] = []

    def opener(request: object, **_kwargs: object) -> FakeProviderResponse:
        observed_urls.append(request.full_url)  # type: ignore[attr-defined]
        return next(responses)

    result = probe_gemini_rest("private-gemini-key", model=model, opener=opener)

    assert result.ok is True
    assert result.model == model
    assert observed_urls == [model_response.geturl(), content_url]
    assert "models/models/" not in observed_urls[1]
    assert "%2F" not in observed_urls[1]


@pytest.mark.parametrize(("error_code", "expected_kind", "retryable"), [
    ("auth_invalid", "auth_invalid", False),
    ("account_limited", "account_limited", True),
    ("model_unavailable", "model_unavailable", False),
    ("provider_unavailable", "provider_unavailable", True),
    ("runner_failed", "runner_failed", False),
    ("private_unclassified_error", "runner_failed", False),
])
def test_gemini_rest_probe_preserves_fleet_runner_error_semantics(
    error_code: str,
    expected_kind: str,
    retryable: bool,
) -> None:
    model_response = _gemini_models_response()
    responses: list[object] = [model_response, FleetRunnerError(error_code)]

    def opener(*_args: object, **_kwargs: object) -> FakeProviderResponse:
        response = responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    result = probe_gemini_rest("private-gemini-key", opener=opener)

    assert result.ok is False
    assert result.error is not None
    assert result.error.kind == expected_kind
    assert result.error.retryable is retryable
    assert result.error.status_code is None
    assert "private_unclassified_error" not in repr(result)
    assert "private-gemini-key" not in repr(result)


def test_gemini_model_validator_accepts_future_ids_and_rejects_path_injection() -> None:
    assert validate_gemini_probe_model("gemini-9.9-future-preview") == "gemini-9.9-future-preview"
    for value in (
        "",
        "gemini-2.5-flash-lite/other",
        "gemini-2.5-flash-lite:generateContent",
        "gemini-2.5-flash-lite?x=1",
        "https://example.invalid/gemini-2.5-flash-lite",
        "GEMINI-2.5-FLASH-LITE",
        " gemini-2.5-flash-lite",
        "gemini-2.5-flash-lite\n",
        "gemini-" + "a" * 128,
    ):
        with pytest.raises(FleetRunnerError, match="gemini_model_invalid"):
            validate_gemini_probe_model(value)


def test_gemini_rest_probe_rejects_redirects() -> None:
    model_response = _gemini_models_response()
    redirected = FakeProviderResponse("https://example.invalid/private-redirect", b"{}")
    responses = iter([model_response, redirected])

    result = probe_gemini_rest(
        "private-gemini-key",
        opener=lambda *_args, **_kwargs: next(responses),
    )

    assert result.ok is False
    assert result.error is not None
    assert result.error.kind == "provider_unavailable"
    assert result.error.diagnostic_code == "gemini_probe_generate_content_redirect_rejected"
    assert getattr(result, "endpoint_role", None) == "generate_content"
    assert getattr(result, "http_class", None) == "transport"
    assert "private-redirect" not in repr(result)
    assert model_response.closed is True
    assert redirected.closed is True


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
