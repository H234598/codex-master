from __future__ import annotations

import json
import os
import re
import tempfile
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from typing import Literal
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from unicodedata import category

from .fleet_registry import AgentDescriptor, Provider, RunnerKind
from .fleet_headless import MAX_HEADLESS_TIMEOUT_SECONDS, HeadlessJob, HeadlessJobRegistry, run_bounded_process


MAX_GEMINI_LINE_BYTES = 1024 * 1024
MAX_GEMINI_EVENTS = 10_000
MAX_GEMINI_RESPONSE_BYTES = 1024 * 1024
MAX_USAGE_TOKENS = 2**63 - 1
MAX_PROVIDER_RESPONSE_BYTES = 1024 * 1024
MAX_PROVIDER_MODELS = 1000
PROVIDER_HTTP_TIMEOUT_SECONDS = 5
GEMINI_PROBE_TIMEOUT_SECONDS = 30
GEMINI_DEFAULT_LIGHT_MODEL = "gemini-3.1-flash-lite"
OLLAMA_MODELS_URL = "http://127.0.0.1:11434/api/tags"
HUGGINGFACE_MODELS_URL = "https://router.huggingface.co/v1/models"
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
class ProviderModelsResult:
    provider: Provider
    available: bool
    models: tuple[Mapping[str, object], ...]
    error: str | None

    def __post_init__(self) -> None:
        object.__setattr__(self, "models", tuple(dict(model) for model in self.models))


class _RedirectRejected(FleetRunnerError):
    pass


class _RejectRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, *_args: object, **_kwargs: object) -> None:
        raise _RedirectRejected("redirect_rejected")


@dataclass(frozen=True, slots=True)
class ProviderError:
    kind: Literal[
        "account_limited", "auth_invalid", "secret_missing", "provider_unavailable", "model_unavailable",
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

    def __post_init__(self) -> None:
        object.__setattr__(self, "argv", tuple(self.argv))
        object.__setattr__(self, "env", MappingProxyType(dict(self.env)))
        object.__setattr__(self, "unset_env", frozenset(self.unset_env))


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
        return RunnerPlan("persistent_tui", (command, "-m", agent.model),
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
        model = GEMINI_DEFAULT_LIGHT_MODEL if agent.model in {"auto", "auto-gemini-3", "flash-lite"} else agent.model
        return RunnerPlan(
            "headless_job",
            (command, "--output-format", "stream-json", "--model", model, "--prompt", ""),
            MappingProxyType({
                "HOME": str(agent.home),
                "GEMINI_CLI_HOME": str(agent.home),
                "GEMINI_CLI_TRUST_WORKSPACE": "true",
            }),
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
            if complete:
                _fail("invalid_gemini_jsonl")
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
        return metadata.get("installed") is True and metadata.get("supports_tools") is True
    if provider is Provider.HUGGINGFACE_INFERENCE:
        return (metadata.get("supports_tools") is True and metadata.get("supports_responses") is True
                and metadata.get("provider_available") is True)
    if provider in {Provider.GEMINI_API, Provider.OPENAI_API, Provider.OPENAI_CHATGPT}:
        return metadata.get("probe_ok") is True and metadata.get("supports_tools") is True
    return False


def _provider_model_name(value: object) -> str | None:
    if not isinstance(value, str) or not 1 <= len(value) <= 200:
        return None
    if any(category(character) == "Cc" for character in value):
        return None
    try:
        value.encode("utf-8")
    except UnicodeError:
        return None
    return value


def _provider_json_body(response: object, expected_url: str) -> object:
    geturl = getattr(response, "geturl", None)
    if callable(geturl) and geturl() != expected_url:
        raise _RedirectRejected("redirect_rejected")
    headers = getattr(response, "headers", None)
    if headers is not None:
        getheader = getattr(headers, "get", None)
        if callable(getheader):
            content_length = getheader("Content-Length")
            if content_length is not None:
                try:
                    advertised = int(content_length)
                except (TypeError, ValueError):
                    raise FleetRunnerError("provider_response_invalid") from None
                if advertised > MAX_PROVIDER_RESPONSE_BYTES:
                    raise FleetRunnerError("provider_response_too_large")
    read = getattr(response, "read", None)
    if not callable(read):
        raise FleetRunnerError("provider_response_invalid")
    body = read(MAX_PROVIDER_RESPONSE_BYTES + 1)
    if not isinstance(body, bytes) or len(body) > MAX_PROVIDER_RESPONSE_BYTES:
        raise FleetRunnerError("provider_response_too_large")
    try:
        return json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise FleetRunnerError("provider_response_invalid") from None


def _provider_http_json(
    url: str,
    *,
    secret: str | None = None,
    opener: Callable[..., object] | None = None,
) -> object:
    if secret is not None:
        if not isinstance(secret, str) or not 1 <= len(secret.encode("utf-8")) <= MAX_PROVIDER_RESPONSE_BYTES:
            raise FleetRunnerError("secret_invalid")
    headers = {"Accept": "application/json"}
    if secret is not None:
        headers["Authorization"] = f"Bearer {secret}"
    request = Request(url, headers=headers, method="GET")
    selected_opener = opener
    if selected_opener is None:
        selected_opener = build_opener(ProxyHandler({}), _RejectRedirectHandler()).open
    response: object | None = None
    try:
        response = selected_opener(request, timeout=PROVIDER_HTTP_TIMEOUT_SECONDS)
        status = getattr(response, "status", None)
        if status is None:
            getcode = getattr(response, "getcode", None)
            status = getcode() if callable(getcode) else None
        if isinstance(status, int) and not 200 <= status < 300:
            if status in {401, 403}:
                raise FleetRunnerError("auth_invalid")
            if status == 429:
                raise FleetRunnerError("account_limited")
            raise FleetRunnerError("provider_unavailable")
        return _provider_json_body(response, url)
    except _RedirectRejected:
        raise
    except FleetRunnerError:
        raise
    except HTTPError as exc:
        if exc.code in {401, 403}:
            raise FleetRunnerError("auth_invalid") from None
        if exc.code == 429:
            raise FleetRunnerError("account_limited") from None
        raise FleetRunnerError("provider_unavailable") from None
    except (OSError, URLError, TimeoutError, ValueError, TypeError):
        raise FleetRunnerError("provider_unavailable") from None
    finally:
        close = getattr(response, "close", None)
        if callable(close):
            close()


def _provider_models_payload(raw: object) -> list[object]:
    if isinstance(raw, list):
        models = raw
    elif isinstance(raw, Mapping):
        models = raw.get("data")
        if models is None:
            models = raw.get("models")
    else:
        models = None
    if not isinstance(models, list):
        raise FleetRunnerError("provider_response_invalid")
    if len(models) > MAX_PROVIDER_MODELS:
        raise FleetRunnerError("provider_model_limit_exceeded")
    return models


def _ollama_model_result(raw: object) -> tuple[Mapping[str, object], ...]:
    models: list[Mapping[str, object]] = []
    seen: set[str] = set()
    for item in _provider_models_payload(raw):
        if not isinstance(item, Mapping):
            raise FleetRunnerError("provider_response_invalid")
        name = _provider_model_name(item.get("name"))
        if name is None:
            raise FleetRunnerError("provider_response_invalid")
        if name in seen:
            continue
        seen.add(name)
        capabilities = item.get("capabilities")
        supports_tools = isinstance(capabilities, list) and "tools" in capabilities
        metadata = {"installed": True, "supports_tools": supports_tools}
        models.append({
            "id": name,
            "installed": True,
            "supports_tools": supports_tools,
            "agentic": model_is_agentic(Provider.OLLAMA_LOCAL, metadata),
        })
    return tuple(models)


def _capability(item: Mapping[str, object], *names: str) -> bool:
    for name in names:
        value = item.get(name)
        if value is True:
            return True
        nested = item.get("capabilities")
        if isinstance(nested, Mapping) and nested.get(name) is True:
            return True
    return False


def _huggingface_model_result(raw: object) -> tuple[Mapping[str, object], ...]:
    models: list[Mapping[str, object]] = []
    seen: set[str] = set()
    for item in _provider_models_payload(raw):
        if not isinstance(item, Mapping):
            raise FleetRunnerError("provider_response_invalid")
        name = _provider_model_name(item.get("id", item.get("model", item.get("name"))))
        if name is None:
            raise FleetRunnerError("provider_response_invalid")
        if name in seen:
            continue
        seen.add(name)
        metadata = {
            "supports_tools": _capability(item, "supports_tools"),
            "supports_responses": _capability(item, "supports_responses"),
            "provider_available": item.get("provider_available") is True,
        }
        models.append({
            "id": name,
            **metadata,
            "agentic": model_is_agentic(Provider.HUGGINGFACE_INFERENCE, metadata),
        })
    return tuple(models)


def probe_ollama_models(
    *,
    opener: Callable[..., object] | None = None,
) -> ProviderModelsResult:
    try:
        raw = _provider_http_json(OLLAMA_MODELS_URL, opener=opener)
        models = _ollama_model_result(raw)
    except FleetRunnerError as exc:
        return ProviderModelsResult(Provider.OLLAMA_LOCAL, False, (), exc.code)
    return ProviderModelsResult(Provider.OLLAMA_LOCAL, True, models, None)


def probe_huggingface_models(
    secret: str | None,
    *,
    opener: Callable[..., object] | None = None,
) -> ProviderModelsResult:
    if secret is None:
        return ProviderModelsResult(Provider.HUGGINGFACE_INFERENCE, False, (), "secret_missing")
    try:
        raw = _provider_http_json(HUGGINGFACE_MODELS_URL, secret=secret, opener=opener)
        models = _huggingface_model_result(raw)
    except FleetRunnerError as exc:
        return ProviderModelsResult(Provider.HUGGINGFACE_INFERENCE, False, (), exc.code)
    return ProviderModelsResult(Provider.HUGGINGFACE_INFERENCE, True, models, None)


def _gemini_probe_settings(home: Path) -> None:
    gemini_home = home / ".gemini"
    policy_home = gemini_home / "policies"
    gemini_home.mkdir(mode=0o700)
    policy_home.mkdir(mode=0o700)
    settings = {
        "advanced": {"autoConfigureMemory": False, "ignoreLocalEnv": True},
        "general": {
            "enableAutoUpdate": False,
            "enableAutoUpdateNotification": False,
            "maxAttempts": 1,
            "retryFetchErrors": False,
        },
        "privacy": {"usageStatisticsEnabled": False},
        "security": {"auth": {"enforcedType": "gemini-api-key"}},
    }
    settings_path = gemini_home / "settings.json"
    settings_path.write_text(json.dumps(settings, sort_keys=True) + "\n", encoding="utf-8")
    settings_path.chmod(0o600)
    policy_path = policy_home / "codex-master.toml"
    policy_path.write_text('approvalMode = "deny"\n', encoding="utf-8")
    policy_path.chmod(0o600)


def probe_gemini_cli(
    secret: str,
    executable: Path,
    *,
    model: str | None = None,
    timeout_seconds: float = GEMINI_PROBE_TIMEOUT_SECONDS,
    popen_factory: Callable[..., object] | None = None,
) -> ProbeResult:
    """Run one bounded, non-writing Gemini capability probe.

    The prompt is written only to stdin.  The temporary Gemini home and
    allowlisted child environment prevent account settings, foreign auth
    variables, prompts, or raw output from crossing the probe boundary.
    """

    if not isinstance(secret, str) or not 1 <= len(secret.encode("utf-8")) <= MAX_PROVIDER_RESPONSE_BYTES:
        return ProbeResult(
            Provider.GEMINI_API, False, None, False,
            ProviderError("auth_invalid", False, None, None),
        )
    try:
        command = _safe_executable(executable)
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise FleetRunnerError("runner_unavailable")
        if model is not None and _provider_model_name(model) is None:
            raise FleetRunnerError("model_unavailable")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not 0 < timeout_seconds <= MAX_HEADLESS_TIMEOUT_SECONDS
        ):
            raise FleetRunnerError("runner_failed")
    except FleetRunnerError as exc:
        kind = "model_unavailable" if exc.args == ("model_unavailable",) else "provider_unavailable"
        return ProbeResult(Provider.GEMINI_API, False, None, False, ProviderError(kind, False, None, None))
    probe_home_path: Path | None = None
    env: dict[str, str] = {}
    result = None
    registry = HeadlessJobRegistry()
    job = HeadlessJob("gemini-provider-probe", "provider-probe", None, time.monotonic(), 0)
    try:
        with tempfile.TemporaryDirectory(prefix="codex-master-gemini-probe-") as temporary_root:
            probe_home_path = Path(temporary_root)
            probe_home_path.chmod(0o700)
            _gemini_probe_settings(probe_home_path)
            for name in ("PATH", "LANG", "LC_ALL", "TZ", "TERM"):
                value = os.environ.get(name)
                if value:
                    env[name] = value
            env.update({
                "HOME": str(probe_home_path),
                "GEMINI_CLI_HOME": str(probe_home_path),
                "GEMINI_API_KEY": secret,
                "GEMINI_CLI_TRUST_WORKSPACE": "true",
            })
            argv = [command, "--output-format", "stream-json", "--prompt", "", "--approval-mode=plan",
                    "--model", model or GEMINI_DEFAULT_LIGHT_MODEL]
            registry.register(job)
            result = run_bounded_process(
                job,
                tuple(argv),
                "Reply with exactly OK. Do not modify files or use tools.",
                env,
                registry,
                timeout_seconds=float(timeout_seconds),
                popen_factory=popen_factory,
            )
    except Exception:
        return ProbeResult(
            Provider.GEMINI_API, False, None, False,
            ProviderError("provider_unavailable", True, None, None),
        )
    finally:
        env.pop("GEMINI_API_KEY", None)
        env.clear()
        if result is not None:
            registry.finish(job, result)

    if result.timed_out:
        return ProbeResult(
            Provider.GEMINI_API, False, None, False,
            ProviderError("provider_unavailable", True, None, None),
        )
    try:
        parsed = parse_gemini_jsonl(result.stdout.decode("utf-8").splitlines())
    except (FleetRunnerError, UnicodeDecodeError):
        return ProbeResult(
            Provider.GEMINI_API, False, None, False,
            ProviderError("runner_failed", False, None, None),
        )
    if parsed.error is not None:
        return ProbeResult(Provider.GEMINI_API, False, parsed.model, False, parsed.error)
    if result.returncode != 0 or result.stdout_truncated or result.stderr_truncated:
        return ProbeResult(
            Provider.GEMINI_API, False, parsed.model, False,
            ProviderError("runner_failed", False, None, None),
        )
    if not isinstance(parsed.model, str) or not parsed.model:
        return ProbeResult(
            Provider.GEMINI_API, False, None, False,
            ProviderError("model_unavailable", False, None, None),
        )
    return ProbeResult(Provider.GEMINI_API, True, parsed.model, True, None)


def probe_provider_models(
    provider: Provider,
    *,
    secret: str | None = None,
    opener: Callable[..., object] | None = None,
) -> ProviderModelsResult:
    if provider is Provider.OLLAMA_LOCAL:
        return probe_ollama_models(opener=opener)
    if provider is Provider.HUGGINGFACE_INFERENCE:
        return probe_huggingface_models(secret, opener=opener)
    return ProviderModelsResult(provider, False, (), "unsupported_provider")
