from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from typing import Literal
from unicodedata import category

from .fleet_registry import AgentDescriptor, Provider, RunnerKind


MAX_GEMINI_LINE_BYTES = 1024 * 1024
MAX_GEMINI_EVENTS = 10_000
MAX_GEMINI_RESPONSE_BYTES = 1024 * 1024
MAX_USAGE_TOKENS = 2**63 - 1
_SECRET_ENV_NAMES = frozenset({
    "OPENAI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY", "GOOGLE_APPLICATION_CREDENTIALS",
    "GOOGLE_CLOUD_PROJECT", "GOOGLE_CLOUD_LOCATION", "GOOGLE_GENAI_USE_VERTEXAI", "HF_TOKEN",
})
_RFC3339_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\Z")


class FleetRunnerError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class ProviderError:
    kind: Literal[
        "account_limited", "auth_invalid", "provider_unavailable", "model_unavailable",
        "runner_failed",
    ]
    retryable: bool
    status_code: int | None
    reset_at_utc: str | None


@dataclass(frozen=True, slots=True)
class ProbeResult:
    provider: Provider
    ok: bool
    model: str | None
    supports_tools: bool
    error: ProviderError | None


@dataclass(frozen=True, slots=True)
class RunnerPlan:
    mode: Literal["persistent_tui", "headless_job"]
    argv: tuple[str, ...]
    env: Mapping[str, str]
    unset_env: frozenset[str]
    secret_env_name: str | None


@dataclass(frozen=True, slots=True)
class GeminiStreamResult:
    response: str
    session_id: str | None
    model: str | None
    input_tokens: int | None
    output_tokens: int | None
    tool_call_count: int
    event_count: int
    unknown_event_count: int
    error: ProviderError | None


def _fail(code: str) -> None:
    raise FleetRunnerError(code)


def _safe_executable(executable: Path) -> str:
    if not isinstance(executable, Path) or not executable.is_absolute():
        _fail("invalid_executable")
    value = str(executable)
    try:
        value.encode("utf-8")
    except UnicodeError:
        _fail("invalid_executable")
    if any(category(character) == "Cc" for character in value):
        _fail("invalid_executable")
    return value


def _plan_env(secret_env_name: str | None) -> frozenset[str]:
    return _SECRET_ENV_NAMES - ({secret_env_name} if secret_env_name is not None else set())


def build_runner_plan(agent: AgentDescriptor, executable: Path) -> RunnerPlan:
    command = _safe_executable(executable)
    if not isinstance(agent, AgentDescriptor):
        _fail("invalid_agent")
    if agent.provider is Provider.OPENAI_CHATGPT and agent.runner is RunnerKind.CODEX_CLI:
        return RunnerPlan("persistent_tui", (command, "-m", agent.model),
                          MappingProxyType({"CODEX_HOME": str(agent.home)}), _plan_env(None), None)
    if agent.provider is Provider.OPENAI_API and agent.runner is RunnerKind.CODEX_CLI:
        return RunnerPlan("persistent_tui", (command, "-m", agent.model),
                          MappingProxyType({"CODEX_HOME": str(agent.home)}),
                          _plan_env("OPENAI_API_KEY"), "OPENAI_API_KEY")
    if agent.provider is Provider.OLLAMA_LOCAL and agent.runner is RunnerKind.CODEX_CLI:
        return RunnerPlan("persistent_tui", (command, "--oss", "--local-provider", "ollama", "-m", agent.model),
                          MappingProxyType({"CODEX_HOME": str(agent.home)}), _plan_env(None), None)
    if agent.provider is Provider.HUGGINGFACE_INFERENCE and agent.runner is RunnerKind.CODEX_CLI:
        return RunnerPlan(
            "persistent_tui",
            (command, "-m", agent.model, "-c", 'model_provider="huggingface"', "-c",
             'base_url="https://router.huggingface.co/v1"', "-c", 'env_key="HF_TOKEN"', "-c",
             'wire_api="responses"'),
            MappingProxyType({"CODEX_HOME": str(agent.home)}), _plan_env("HF_TOKEN"), "HF_TOKEN",
        )
    if agent.provider is Provider.GEMINI_API and agent.runner is RunnerKind.GEMINI_CLI and agent.account_id:
        return RunnerPlan(
            "headless_job",
            (command, "--output-format", "stream-json", "--model", agent.model),
            MappingProxyType({"HOME": str(agent.home), "GEMINI_CLI_HOME": str(agent.home)}),
            _plan_env("GEMINI_API_KEY"), "GEMINI_API_KEY",
        )
    _fail("invalid_agent")


def _mapping(value: object) -> Mapping[str, object] | None:
    if isinstance(value, Mapping) and all(isinstance(key, str) for key in value):
        return value
    return None


def _status_code(payload: Mapping[str, object]) -> int | None:
    value = payload.get("code")
    if isinstance(value, int) and not isinstance(value, bool) and 100 <= value <= 599:
        return value
    return None


def _valid_time(value: object) -> str | None:
    if not isinstance(value, str) or len(value) > 40 or not _RFC3339_RE.fullmatch(value):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return value


def classify_provider_error(provider: Provider, payload: object, stderr: str) -> ProviderError:
    del provider, stderr
    raw = _mapping(payload)
    nested = _mapping(raw.get("error")) if raw is not None else None
    details = nested if nested is not None else raw
    if details is None:
        return ProviderError("runner_failed", False, None, None)
    status_code = _status_code(details)
    status = details.get("status")
    status_name = status if isinstance(status, str) else ""
    reset_at_utc = _valid_time(details.get("reset_at_utc"))
    if (status_code == 429 or status_name in {"RESOURCE_EXHAUSTED", "BUDGET_EXHAUSTED",
                                               "ADMINISTRATIVE_QUOTA_LOCKED"}
            or details.get("budget_exhausted") is True
            or details.get("administrative_quota_lock") is True):
        return ProviderError("account_limited", True, status_code, reset_at_utc)
    if status_code in {401, 403} or status_name in {"UNAUTHENTICATED", "PERMISSION_DENIED"}:
        return ProviderError("auth_invalid", False, status_code, reset_at_utc)
    if (status_code is not None and 500 <= status_code <= 599
            or status_name in {"UNAVAILABLE", "TRANSPORT_UNAVAILABLE"}
            or details.get("transport_error") is True):
        return ProviderError("provider_unavailable", True, status_code, reset_at_utc)
    if status_name in {"MODEL_NOT_FOUND", "MODEL_UNAVAILABLE"} or details.get("model_not_found") is True:
        return ProviderError("model_unavailable", False, status_code, reset_at_utc)
    return ProviderError("runner_failed", False, status_code, reset_at_utc)


def _usage(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_USAGE_TOKENS:
        _fail("invalid_gemini_usage")
    return value


def _response_part(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        value.encode("utf-8")
    except UnicodeError:
        _fail("invalid_gemini_jsonl")
    return value


def parse_gemini_jsonl(lines: Iterable[str]) -> GeminiStreamResult:
    response_parts: list[str] = []
    response_bytes = 0
    session_id: str | None = None
    model: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    tool_call_count = 0
    event_count = 0
    unknown_event_count = 0
    provider_error: ProviderError | None = None
    complete = False
    final_response: str | None = None
    for line in lines:
        if not isinstance(line, str):
            _fail("invalid_gemini_jsonl")
        try:
            line_bytes = line.encode("utf-8")
        except UnicodeError:
            _fail("invalid_gemini_jsonl")
        if len(line_bytes) > MAX_GEMINI_LINE_BYTES:
            _fail("gemini_line_too_large")
        event_count += 1
        if event_count > MAX_GEMINI_EVENTS:
            _fail("gemini_event_limit_exceeded")
        try:
            event = json.loads(line)
        except (UnicodeError, json.JSONDecodeError, RecursionError):
            _fail("invalid_gemini_jsonl")
        raw = _mapping(event)
        if raw is None:
            _fail("invalid_gemini_jsonl")
        event_type = raw.get("type")
        if event_type == "init":
            candidate_session_id = raw.get("session_id")
            candidate_model = raw.get("model")
            if isinstance(candidate_session_id, str):
                session_id = candidate_session_id
            if isinstance(candidate_model, str):
                model = candidate_model
        elif event_type == "message":
            if raw.get("role") == "assistant":
                content = _response_part(raw.get("content"))
                if content is not None:
                    response_bytes += len(content.encode("utf-8"))
                    if response_bytes > MAX_GEMINI_RESPONSE_BYTES:
                        _fail("gemini_response_too_large")
                    response_parts.append(content)
        elif event_type == "tool_use":
            tool_call_count += 1
        elif event_type == "tool_result":
            pass
        elif event_type == "error":
            provider_error = classify_provider_error(Provider.GEMINI_API, raw, "")
        elif event_type == "result":
            complete = True
            content = _response_part(raw.get("response"))
            if content is not None:
                response_bytes += len(content.encode("utf-8"))
                if response_bytes > MAX_GEMINI_RESPONSE_BYTES:
                    _fail("gemini_response_too_large")
                final_response = content
            stats = _mapping(raw.get("stats"))
            if stats is not None:
                input_tokens = _usage(stats.get("input_tokens"))
                output_tokens = _usage(stats.get("output_tokens"))
        else:
            unknown_event_count += 1
    if not complete:
        _fail("gemini_result_missing")
    return GeminiStreamResult(final_response if final_response is not None else "".join(response_parts), session_id,
                              model, input_tokens, output_tokens, tool_call_count, event_count,
                              unknown_event_count, provider_error)


def model_is_agentic(provider: Provider, metadata: Mapping[str, object]) -> bool:
    if provider is Provider.OLLAMA_LOCAL:
        return metadata.get("installed") is True
    if provider is Provider.HUGGINGFACE_INFERENCE:
        return (metadata.get("supports_tools") is True and metadata.get("supports_responses") is True
                and metadata.get("provider_available") is True)
    if provider in {Provider.GEMINI_API, Provider.OPENAI_API, Provider.OPENAI_CHATGPT}:
        return metadata.get("probe_ok") is True and metadata.get("supports_tools") is True
    return False
