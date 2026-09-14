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
from typing import Final, Literal
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from unicodedata import category

from .dynamic_teamlead import (
    DynamicTeamleadPlan,
    prepare_dynamic_teamlead,
    require_committed_home_attestation,
)
from .dynamic_teamlead_coordinator import DynamicTeamleadLaunchPlan
from .fleet_home_broker_client import AttestedHome
from .fleet_home_broker_identity import BrokerIdentity
from .fleet_home_broker_protocol import BindingExpectation, PrincipalBinding
from .fleet_registry import (
    AgentDescriptor,
    FleetRuntimePrincipalV2,
    FleetSnapshotV2,
    Provider,
    RunnerKind,
)
from .fleet_headless import (
    MAX_HEADLESS_TIMEOUT_SECONDS,
    HeadlessJob,
    HeadlessJobError,
    HeadlessJobRegistry,
    run_bounded_process,
)


MAX_GEMINI_LINE_BYTES = 1024 * 1024
MAX_GEMINI_EVENTS = 10_000
MAX_GEMINI_RESPONSE_BYTES = 1024 * 1024
MAX_USAGE_TOKENS = 2**63 - 1
MAX_PROVIDER_RESPONSE_BYTES = 1024 * 1024
MAX_PROVIDER_MODELS = 1000
PROVIDER_HTTP_TIMEOUT_SECONDS = 5
GEMINI_PROBE_TIMEOUT_SECONDS = 90
GEMINI_DEFAULT_LIGHT_MODEL = "gemini-3.1-flash-lite"
GEMINI_MODELS_URL = "https://generativelanguage.googleapis.com/v1beta/models"
MAX_GEMINI_MODEL_ID_BYTES = 128
MAX_GEMINI_MODELS_PAGES = 4
MAX_GEMINI_MODELS = 256
MAX_GEMINI_MODELS_PAGE_SIZE = 100
MAX_GEMINI_PAGE_TOKEN_BYTES = 512
MAX_GEMINI_MODELS_RESPONSE_BYTES = 256 * 1024
MAX_GEMINI_PROBE_REQUEST_BYTES = 4096
MAX_GEMINI_PROBE_RESPONSE_BYTES = 64 * 1024
OLLAMA_MODELS_URL = "http://127.0.0.1:11434/api/tags"
HUGGINGFACE_MODELS_URL = "https://router.huggingface.co/v1/models"
_GEMINI_MODEL_ID_RE = re.compile(r"gemini-[a-z0-9]+(?:[.-][a-z0-9]+)*\Z")
_GEMINI_GENERATION_METHODS: Final[frozenset[str]] = frozenset(
    {
        "batchEmbedContents",
        "countTokens",
        "embedContent",
        "generateAnswer",
        "generateContent",
        "predict",
        "predictLongRunning",
        "streamGenerateContent",
    }
)
_SECRET_ENV_NAMES = frozenset(
    {
        "OPENAI_API_KEY",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GOOGLE_CLOUD_PROJECT",
        "GOOGLE_CLOUD_LOCATION",
        "GOOGLE_GENAI_USE_VERTEXAI",
        "HF_TOKEN",
    }
)
_RFC3339_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\Z"
)
_QUOTA_FAILURE_TYPE: Final = "type.googleapis.com/google.rpc.QuotaFailure"
_RETRY_INFO_TYPE: Final = "type.googleapis.com/google.rpc.RetryInfo"
_QUOTA_SCOPE_ACCOUNT: Final = "account"
_QUOTA_SCOPE_MODEL: Final = "model"
_QUOTA_SCOPE_UNKNOWN: Final = "unknown"
_MAX_RETRY_AFTER_SECONDS: Final = 3600
ProbeDiagnosticCode = Literal[
    "gemini_probe_structured_response",
    "gemini_probe_process_timeout",
    "gemini_probe_runner_failure",
    "gemini_probe_jsonl_terminal_invalid",
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
]
ProbeEndpointRole = Literal["generate_content"]
ProbeHttpClass = Literal["2xx", "4xx", "5xx", "transport"]
ProbeProcessPhase = Literal[
    "gemini_probe_runner_not_started_or_failed",
    "gemini_probe_timeout_no_output",
    "gemini_probe_timeout_structured_no_terminal",
    "gemini_probe_timeout_output_unclassified",
    "gemini_probe_process_group_unreaped",
    "gemini_probe_exit_nonzero",
    "gemini_probe_normal_exit",
    "gemini_probe_exit_output_pipe_open",
]
ProbeOutputShape = Literal[
    "gemini_probe_output_none",
    "gemini_probe_output_stderr_only",
    "gemini_probe_output_stdout_stderr",
    "gemini_probe_output_stdout_jsonl_incomplete",
    "gemini_probe_output_stdout_unclassified",
    "gemini_probe_output_stdout_terminal",
    "gemini_probe_output_truncated_or_pipe_open",
]
ProbeStdoutShape = Literal[
    "gemini_probe_stdout_terminal_jsonl",
    "gemini_probe_stdout_jsonl_incomplete",
    "gemini_probe_stdout_unclassified",
]
ProbeStdoutEventClass = Literal[
    "gemini_probe_stdout_event_init",
    "gemini_probe_stdout_event_user_message",
    "gemini_probe_stdout_event_assistant_message",
    "gemini_probe_stdout_event_tool_use",
    "gemini_probe_stdout_event_tool_result",
    "gemini_probe_stdout_event_error",
]
GEMINI_PROBE_DIAGNOSTIC_CODES: Final[frozenset[ProbeDiagnosticCode]] = frozenset(
    {
        "gemini_probe_structured_response",
        "gemini_probe_process_timeout",
        "gemini_probe_runner_failure",
        "gemini_probe_jsonl_terminal_invalid",
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
    }
)
GEMINI_PROBE_PROCESS_PHASES: Final[frozenset[ProbeProcessPhase]] = frozenset(
    {
        "gemini_probe_runner_not_started_or_failed",
        "gemini_probe_timeout_no_output",
        "gemini_probe_timeout_structured_no_terminal",
        "gemini_probe_timeout_output_unclassified",
        "gemini_probe_process_group_unreaped",
        "gemini_probe_exit_nonzero",
        "gemini_probe_normal_exit",
        "gemini_probe_exit_output_pipe_open",
    }
)
GEMINI_PROBE_OUTPUT_SHAPES: Final[frozenset[ProbeOutputShape]] = frozenset(
    {
        "gemini_probe_output_none",
        "gemini_probe_output_stderr_only",
        "gemini_probe_output_stdout_stderr",
        "gemini_probe_output_stdout_jsonl_incomplete",
        "gemini_probe_output_stdout_unclassified",
        "gemini_probe_output_stdout_terminal",
        "gemini_probe_output_truncated_or_pipe_open",
    }
)
GEMINI_PROBE_STDOUT_SHAPES: Final[frozenset[ProbeStdoutShape]] = frozenset(
    {
        "gemini_probe_stdout_terminal_jsonl",
        "gemini_probe_stdout_jsonl_incomplete",
        "gemini_probe_stdout_unclassified",
    }
)
GEMINI_PROBE_STDOUT_EVENT_CLASSES: Final[frozenset[ProbeStdoutEventClass]] = frozenset(
    {
        "gemini_probe_stdout_event_init",
        "gemini_probe_stdout_event_user_message",
        "gemini_probe_stdout_event_assistant_message",
        "gemini_probe_stdout_event_tool_use",
        "gemini_probe_stdout_event_tool_result",
        "gemini_probe_stdout_event_error",
    }
)


def normalize_gemini_probe_diagnostic_code(value: object) -> ProbeDiagnosticCode | None:
    return (
        value
        if isinstance(value, str) and value in GEMINI_PROBE_DIAGNOSTIC_CODES
        else None
    )


def normalize_gemini_probe_process_phase(value: object) -> ProbeProcessPhase | None:
    return (
        value
        if isinstance(value, str) and value in GEMINI_PROBE_PROCESS_PHASES
        else None
    )


def normalize_gemini_probe_output_shape(value: object) -> ProbeOutputShape | None:
    return (
        value
        if isinstance(value, str) and value in GEMINI_PROBE_OUTPUT_SHAPES
        else None
    )


def normalize_gemini_probe_stdout_shape(value: object) -> ProbeStdoutShape | None:
    return (
        value
        if isinstance(value, str) and value in GEMINI_PROBE_STDOUT_SHAPES
        else None
    )


def normalize_gemini_probe_stdout_event_class(
    value: object,
) -> ProbeStdoutEventClass | None:
    return (
        value
        if isinstance(value, str) and value in GEMINI_PROBE_STDOUT_EVENT_CLASSES
        else None
    )


class FleetRunnerError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def validate_gemini_probe_model(model: object | None) -> str:
    candidate = GEMINI_DEFAULT_LIGHT_MODEL if model is None else model
    if not isinstance(candidate, str):
        raise FleetRunnerError("gemini_model_invalid")
    try:
        valid = (
            1 <= len(candidate.encode("utf-8")) <= MAX_GEMINI_MODEL_ID_BYTES
            and _GEMINI_MODEL_ID_RE.fullmatch(candidate) is not None
        )
    except UnicodeError:
        valid = False
    if not valid:
        raise FleetRunnerError("gemini_model_invalid")
    return candidate


@dataclass(frozen=True, slots=True)
class ProviderModelsResult:
    provider: Provider
    available: bool
    models: tuple[Mapping[str, object], ...]
    error: str | None
    provider_error: ProviderError | None = None
    http_class: ProbeHttpClass | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "models", tuple(dict(model) for model in self.models))
        if not isinstance(self.provider_error, ProviderError):
            object.__setattr__(self, "provider_error", None)
        if self.http_class not in {"2xx", "4xx", "5xx", "transport"}:
            object.__setattr__(self, "http_class", None)


class _RedirectRejected(FleetRunnerError):
    pass


class _RejectRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, *_args: object, **_kwargs: object) -> None:
        raise _RedirectRejected("redirect_rejected")


@dataclass(frozen=True, slots=True)
class ProviderErrorQuotaObservation:
    scope: Literal["model", "account", "unknown"]
    retry_after_seconds: int | None


@dataclass(frozen=True, slots=True)
class ProviderError:
    kind: Literal[
        "account_limited",
        "auth_invalid",
        "auth_or_billing_denied",
        "secret_missing",
        "provider_unavailable",
        "model_unavailable",
        "runner_failed",
    ]
    retryable: bool
    status_code: int | None
    reset_at_utc: str | None
    quota_observation: ProviderErrorQuotaObservation | None = None
    diagnostic_code: ProbeDiagnosticCode | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "diagnostic_code",
            normalize_gemini_probe_diagnostic_code(self.diagnostic_code),
        )


class _GeminiHttpFailure(FleetRunnerError):
    def __init__(self, error: ProviderError, http_class: ProbeHttpClass) -> None:
        self.error = error
        self.http_class = http_class
        super().__init__(error.kind)


@dataclass(frozen=True, slots=True)
class ProbeResult:
    provider: Provider
    ok: bool
    model: str | None
    supports_tools: bool
    error: ProviderError | None
    process_phase: ProbeProcessPhase | None = None
    process_output_shape: ProbeOutputShape | None = None
    process_stdout_shape: ProbeStdoutShape | None = None
    process_stdout_event_class: ProbeStdoutEventClass | None = None
    process_stdout_error_seen: bool | None = None
    endpoint_role: ProbeEndpointRole | None = None
    http_class: ProbeHttpClass | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "process_phase",
            normalize_gemini_probe_process_phase(self.process_phase),
        )
        object.__setattr__(
            self,
            "process_output_shape",
            normalize_gemini_probe_output_shape(self.process_output_shape),
        )
        object.__setattr__(
            self,
            "process_stdout_shape",
            normalize_gemini_probe_stdout_shape(self.process_stdout_shape),
        )
        object.__setattr__(
            self,
            "process_stdout_event_class",
            normalize_gemini_probe_stdout_event_class(
                self.process_stdout_event_class,
            ),
        )
        if not isinstance(self.process_stdout_error_seen, bool):
            object.__setattr__(self, "process_stdout_error_seen", None)
        if self.endpoint_role != "generate_content":
            object.__setattr__(self, "endpoint_role", None)
        if self.http_class not in {"2xx", "4xx", "5xx", "transport"}:
            object.__setattr__(self, "http_class", None)


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
class DynamicTeamleadRunnerPlan:
    runtime_principal: FleetRuntimePrincipalV2
    expected_principal: PrincipalBinding
    expectation: BindingExpectation
    identity: BrokerIdentity
    home: AttestedHome


def prepare_dynamic_teamlead_runner(launch: object) -> DynamicTeamleadRunnerPlan:
    try:
        if (
            type(launch) is not DynamicTeamleadLaunchPlan
            or type(launch.snapshot) is not FleetSnapshotV2
            or type(launch.snapshot.schema_version) is not int
            or launch.snapshot.schema_version != 2
            or type(launch.teamlead) is not DynamicTeamleadPlan
            or type(launch.expected_principal) is not PrincipalBinding
            or type(launch.expectation) is not BindingExpectation
            or type(launch.identity) is not BrokerIdentity
            or type(launch.home) is not AttestedHome
        ):
            raise ValueError

        prepared = prepare_dynamic_teamlead(
            launch.snapshot,
            launch.teamlead.request,
            launch.teamlead.profile_binding,
        )
        if type(prepared) is not DynamicTeamleadPlan or prepared != launch.teamlead:
            raise ValueError

        runtime_principal = launch.teamlead.principal
        expected_principal = launch.expected_principal
        expectation = launch.expectation
        identity = launch.identity
        home = launch.home
        if type(runtime_principal) is not FleetRuntimePrincipalV2:
            raise ValueError
        if (
            expected_principal.agent_id != runtime_principal.principal_id
            or expectation.agent_id != expected_principal.agent_id
            or expectation.manifest_generation != expected_principal.manifest_generation
            or expectation.unit_generation != expected_principal.unit_generation
            or expectation.fencing_epoch != expected_principal.fencing_epoch
            or identity.agent_id != expected_principal.agent_id
            or identity.manifest_generation != expected_principal.manifest_generation
            or identity.mcs_pair != expected_principal.mcs_pair
            or identity.fencing_epoch != expected_principal.fencing_epoch
            or identity.policy_generation != expectation.policy_generation
            or identity.projection_digest != expectation.projection_digest
        ):
            raise ValueError
        if type(home.fd) is not int or home.fd < 0:
            raise ValueError

        committed_attestation = require_committed_home_attestation(
            home.reply, expectation
        )
        if (
            committed_attestation != home.attestation
            or home.reply.attestation != home.attestation
            or home.reply.transaction.binding != home.attestation.binding
            or home.attestation.binding.principal != expected_principal
            or home.attestation.binding.policy.policy_generation
            != expectation.policy_generation
            or home.attestation.binding.policy.projection_digest
            != expectation.projection_digest
        ):
            raise ValueError
        return DynamicTeamleadRunnerPlan(
            runtime_principal,
            expected_principal,
            expectation,
            identity,
            home,
        )
    except Exception:
        raise FleetRunnerError("dynamic_teamlead_runner_invalid") from None


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
    return _SECRET_ENV_NAMES - (
        {secret_env_name} if secret_env_name is not None else set()
    )


def build_runner_plan(agent: AgentDescriptor, executable: Path) -> RunnerPlan:
    command = _safe_executable(executable)
    if not isinstance(agent, AgentDescriptor):
        _fail("invalid_agent")
    if (
        agent.provider is Provider.OPENAI_CHATGPT
        and agent.runner is RunnerKind.CODEX_CLI
    ):
        return RunnerPlan(
            "persistent_tui",
            (command, "-m", agent.model),
            MappingProxyType({"CODEX_HOME": str(agent.home)}),
            _plan_env(None),
            None,
        )
    if agent.provider is Provider.OPENAI_API and agent.runner is RunnerKind.CODEX_CLI:
        return RunnerPlan(
            "persistent_tui",
            (command, "-m", agent.model),
            MappingProxyType({"CODEX_HOME": str(agent.home)}),
            _plan_env("OPENAI_API_KEY"),
            "OPENAI_API_KEY",
        )
    if agent.provider is Provider.OLLAMA_LOCAL and agent.runner is RunnerKind.CODEX_CLI:
        return RunnerPlan(
            "persistent_tui",
            (command, "-m", agent.model),
            MappingProxyType({"CODEX_HOME": str(agent.home)}),
            _plan_env(None),
            None,
        )
    if (
        agent.provider is Provider.HUGGINGFACE_INFERENCE
        and agent.runner is RunnerKind.CODEX_CLI
    ):
        return RunnerPlan(
            "persistent_tui",
            (
                command,
                "-m",
                agent.model,
                "-c",
                'model_provider="huggingface"',
                "-c",
                'base_url="https://router.huggingface.co/v1"',
                "-c",
                'env_key="HF_TOKEN"',
                "-c",
                'wire_api="responses"',
            ),
            MappingProxyType({"CODEX_HOME": str(agent.home)}),
            _plan_env("HF_TOKEN"),
            "HF_TOKEN",
        )
    if (
        agent.provider is Provider.GEMINI_API
        and agent.runner is RunnerKind.GEMINI_CLI
        and agent.account_id
    ):
        model = (
            GEMINI_DEFAULT_LIGHT_MODEL
            if agent.model in {"auto", "auto-gemini-3", "flash-lite"}
            else agent.model
        )
        return RunnerPlan(
            "headless_job",
            (
                command,
                "--output-format",
                "stream-json",
                "--model",
                model,
                "--prompt",
                "",
            ),
            MappingProxyType(
                {
                    "HOME": str(agent.home),
                    "GEMINI_CLI_HOME": str(agent.home),
                    "GEMINI_CLI_TRUST_WORKSPACE": "true",
                }
            ),
            _plan_env("GEMINI_API_KEY"),
            "GEMINI_API_KEY",
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
    if (
        not isinstance(value, str)
        or len(value) > 40
        or not _RFC3339_RE.fullmatch(value)
    ):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return value


def _parse_retry_delay_seconds(value: object) -> int | None:
    if not isinstance(value, str):
        return None
    if len(value) > 64:
        return None
    match = re.fullmatch(r"(\d+)(?:\.(\d{1,9}))?s", value)
    if match is None:
        return None
    integer_seconds = int(match.group(1))
    if integer_seconds == 0 and match.group(2) is None:
        return None
    fractional = match.group(2)
    if fractional is None or fractional == "":
        seconds = integer_seconds
    else:
        if int(fractional) == 0:
            seconds = integer_seconds
        else:
            seconds = integer_seconds + 1
    if seconds <= 0:
        return None
    if seconds > _MAX_RETRY_AFTER_SECONDS:
        return _MAX_RETRY_AFTER_SECONDS
    return seconds


def _collect_quota_scope(
    details: list[object],
) -> tuple[bool, Literal["model", "account", "unknown"] | None]:
    derived_scopes: set[Literal["model", "account", "unknown"]] = set()
    quota_failure_seen = False
    for item in details:
        detail = _mapping(item)
        if detail is None or detail.get("@type") != _QUOTA_FAILURE_TYPE:
            continue
        quota_failure_seen = True
        violations = detail.get("violations")
        if not isinstance(violations, list):
            return True, _QUOTA_SCOPE_UNKNOWN
        if len(violations) == 0:
            return True, _QUOTA_SCOPE_UNKNOWN
        for raw_violation in violations:
            violation = _mapping(raw_violation)
            if violation is None:
                return True, _QUOTA_SCOPE_UNKNOWN
            dimensions = violation.get("quotaDimensions")
            dimensions_mapping = _mapping(dimensions)
            if dimensions is None:
                return True, _QUOTA_SCOPE_UNKNOWN
            if dimensions_mapping is None:
                return True, _QUOTA_SCOPE_UNKNOWN
            dimensions = dimensions_mapping
            if not dimensions:
                derived_scopes.add(_QUOTA_SCOPE_ACCOUNT)
                continue
            if any(not isinstance(key, str) for key in dimensions.keys()):
                return True, _QUOTA_SCOPE_UNKNOWN
            if any(
                not isinstance(value, str) or not value for value in dimensions.values()
            ):
                return True, _QUOTA_SCOPE_UNKNOWN
            if _QUOTA_SCOPE_MODEL in dimensions:
                derived_scopes.add(_QUOTA_SCOPE_MODEL)
                continue
            return True, _QUOTA_SCOPE_UNKNOWN

    if not quota_failure_seen:
        return False, None
    if len(derived_scopes) == 0:
        return True, _QUOTA_SCOPE_UNKNOWN
    if len(derived_scopes) > 1:
        return True, _QUOTA_SCOPE_UNKNOWN
    return True, next(iter(derived_scopes))


def _collect_retry_seconds(details: list[object]) -> int | None:
    observed: int | None = None
    for item in details:
        detail = _mapping(item)
        if detail is None or detail.get("@type") != _RETRY_INFO_TYPE:
            continue
        retry_seconds = _parse_retry_delay_seconds(detail.get("retryDelay"))
        if retry_seconds is None:
            return None
        if observed is None:
            observed = retry_seconds
        elif observed != retry_seconds:
            return None
    return observed


def _quota_observation(
    payload: Mapping[str, object],
) -> ProviderErrorQuotaObservation | None:
    details = payload.get("details")
    if not isinstance(details, list):
        return ProviderErrorQuotaObservation(_QUOTA_SCOPE_UNKNOWN, None)

    has_quota_scope, scope = _collect_quota_scope(details)
    retry_after_seconds = _collect_retry_seconds(details)
    if not has_quota_scope:
        return ProviderErrorQuotaObservation(_QUOTA_SCOPE_UNKNOWN, None)
    if scope is None:
        return ProviderErrorQuotaObservation(_QUOTA_SCOPE_UNKNOWN, retry_after_seconds)

    return ProviderErrorQuotaObservation(scope, retry_after_seconds)


def classify_provider_error(
    provider: Provider, payload: object, stderr: str
) -> ProviderError:
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
    quota_observation = None
    if status_code == 429:
        quota_observation = _quota_observation(details)
    if (
        status_code == 429
        or status_name
        in {"RESOURCE_EXHAUSTED", "BUDGET_EXHAUSTED", "ADMINISTRATIVE_QUOTA_LOCKED"}
        or details.get("budget_exhausted") is True
        or details.get("administrative_quota_lock") is True
    ):
        return ProviderError(
            "account_limited", True, status_code, reset_at_utc, quota_observation
        )
    if status_code in {401, 403} or status_name in {
        "UNAUTHENTICATED",
        "PERMISSION_DENIED",
    }:
        return ProviderError("auth_invalid", False, status_code, reset_at_utc, None)
    if (
        status_code is not None
        and 500 <= status_code <= 599
        or status_name in {"UNAVAILABLE", "TRANSPORT_UNAVAILABLE"}
        or details.get("transport_error") is True
    ):
        return ProviderError(
            "provider_unavailable", True, status_code, reset_at_utc, None
        )
    if (
        status_name in {"MODEL_NOT_FOUND", "MODEL_UNAVAILABLE"}
        or details.get("model_not_found") is True
    ):
        return ProviderError(
            "model_unavailable", False, status_code, reset_at_utc, None
        )
    return ProviderError("runner_failed", False, status_code, reset_at_utc, None)


def _usage(value: object) -> int | None:
    if value is None:
        return None
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= MAX_USAGE_TOKENS
    ):
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


def _scan_gemini_jsonl(
    lines: Iterable[str],
) -> tuple[
    GeminiStreamResult | None,
    FleetRunnerError | None,
    ProbeStdoutEventClass | None,
    bool,
]:
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
    last_event_class: ProbeStdoutEventClass | None = None
    error_seen = False
    summary_valid = True
    for line in lines:
        if not isinstance(line, str):
            return None, FleetRunnerError("invalid_gemini_jsonl"), None, False
        try:
            line_bytes = line.encode("utf-8")
        except UnicodeError:
            return None, FleetRunnerError("invalid_gemini_jsonl"), None, False
        if len(line_bytes) > MAX_GEMINI_LINE_BYTES:
            return None, FleetRunnerError("gemini_line_too_large"), None, False
        event_count += 1
        if event_count > MAX_GEMINI_EVENTS:
            return None, FleetRunnerError("gemini_event_limit_exceeded"), None, False
        try:
            event = json.loads(line)
        except (UnicodeError, json.JSONDecodeError, RecursionError):
            return None, FleetRunnerError("invalid_gemini_jsonl"), None, False
        raw = _mapping(event)
        if raw is None:
            return None, FleetRunnerError("invalid_gemini_jsonl"), None, False
        event_type = raw.get("type")
        if event_type == "init":
            candidate_session_id = raw.get("session_id")
            candidate_model = raw.get("model")
            if isinstance(candidate_session_id, str):
                session_id = candidate_session_id
            if isinstance(candidate_model, str):
                model = candidate_model
            last_event_class = "gemini_probe_stdout_event_init"
        elif event_type == "message":
            role = raw.get("role")
            if role == "user":
                last_event_class = "gemini_probe_stdout_event_user_message"
            elif role == "assistant":
                last_event_class = "gemini_probe_stdout_event_assistant_message"
            else:
                summary_valid = False
            if raw.get("role") == "assistant":
                content = _response_part(raw.get("content"))
                if content is not None:
                    response_bytes += len(content.encode("utf-8"))
                    if response_bytes > MAX_GEMINI_RESPONSE_BYTES:
                        return (
                            None,
                            FleetRunnerError("gemini_response_too_large"),
                            None,
                            False,
                        )
                    response_parts.append(content)
        elif event_type == "tool_use":
            tool_call_count += 1
            last_event_class = "gemini_probe_stdout_event_tool_use"
        elif event_type == "tool_result":
            last_event_class = "gemini_probe_stdout_event_tool_result"
        elif event_type == "error":
            provider_error = classify_provider_error(Provider.GEMINI_API, raw, "")
            error_seen = True
            last_event_class = "gemini_probe_stdout_event_error"
        elif event_type == "result":
            if complete:
                return None, FleetRunnerError("invalid_gemini_jsonl"), None, False
            complete = True
            content = _response_part(raw.get("response"))
            if content is not None:
                response_bytes += len(content.encode("utf-8"))
                if response_bytes > MAX_GEMINI_RESPONSE_BYTES:
                    return (
                        None,
                        FleetRunnerError("gemini_response_too_large"),
                        None,
                        False,
                    )
                final_response = content
            stats = _mapping(raw.get("stats"))
            if stats is not None:
                input_tokens = _usage(stats.get("input_tokens"))
                output_tokens = _usage(stats.get("output_tokens"))
        else:
            summary_valid = False
            unknown_event_count += 1
    if not complete:
        parse_error = FleetRunnerError("gemini_result_missing")
        return (
            None,
            parse_error,
            last_event_class if summary_valid else None,
            bool(error_seen) if summary_valid else False,
        )
    return (
        GeminiStreamResult(
            final_response if final_response is not None else "".join(response_parts),
            session_id,
            model,
            input_tokens,
            output_tokens,
            tool_call_count,
            event_count,
            unknown_event_count,
            provider_error,
        ),
        None,
        (last_event_class if summary_valid else None),
        bool(error_seen) if summary_valid else False,
    )


def parse_gemini_jsonl(lines: Iterable[str]) -> GeminiStreamResult:
    parsed, error, _event_class, _error_seen = _scan_gemini_jsonl(lines)
    if error is not None:
        raise error
    return parsed


def model_is_agentic(provider: Provider, metadata: Mapping[str, object]) -> bool:
    if provider is Provider.OLLAMA_LOCAL:
        return (
            metadata.get("installed") is True and metadata.get("supports_tools") is True
        )
    if provider is Provider.HUGGINGFACE_INFERENCE:
        return (
            metadata.get("supports_tools") is True
            and metadata.get("supports_responses") is True
            and metadata.get("provider_available") is True
        )
    if provider in {Provider.GEMINI_API, Provider.OPENAI_API, Provider.OPENAI_CHATGPT}:
        return (
            metadata.get("probe_ok") is True and metadata.get("supports_tools") is True
        )
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


def _provider_json_body(
    response: object,
    expected_url: str,
    *,
    max_bytes: int = MAX_PROVIDER_RESPONSE_BYTES,
) -> object:
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
                if advertised > max_bytes:
                    raise FleetRunnerError("provider_response_too_large")
    read = getattr(response, "read", None)
    if not callable(read):
        raise FleetRunnerError("provider_response_invalid")
    body = read(max_bytes + 1)
    if not isinstance(body, bytes) or len(body) > max_bytes:
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
        if (
            not isinstance(secret, str)
            or not 1 <= len(secret.encode("utf-8")) <= MAX_PROVIDER_RESPONSE_BYTES
        ):
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
        models.append(
            {
                "id": name,
                "installed": True,
                "supports_tools": supports_tools,
                "agentic": model_is_agentic(Provider.OLLAMA_LOCAL, metadata),
            }
        )
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
        models.append(
            {
                "id": name,
                **metadata,
                "agentic": model_is_agentic(Provider.HUGGINGFACE_INFERENCE, metadata),
            }
        )
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
        return ProviderModelsResult(
            Provider.HUGGINGFACE_INFERENCE, False, (), "secret_missing"
        )
    try:
        raw = _provider_http_json(HUGGINGFACE_MODELS_URL, secret=secret, opener=opener)
        models = _huggingface_model_result(raw)
    except FleetRunnerError as exc:
        return ProviderModelsResult(Provider.HUGGINGFACE_INFERENCE, False, (), exc.code)
    return ProviderModelsResult(Provider.HUGGINGFACE_INFERENCE, True, models, None)


def _gemini_models_page_url(page_token: str | None = None) -> str:
    params: dict[str, str] = {"pageSize": str(MAX_GEMINI_MODELS_PAGE_SIZE)}
    if page_token is not None:
        if not isinstance(page_token, str):
            raise FleetRunnerError("provider_response_invalid")
        try:
            valid = 1 <= len(
                page_token.encode("utf-8")
            ) <= MAX_GEMINI_PAGE_TOKEN_BYTES and not any(
                category(character) == "Cc" for character in page_token
            )
        except UnicodeError:
            valid = False
        if not valid:
            raise FleetRunnerError("provider_response_invalid")
        params["pageToken"] = page_token
    return f"{GEMINI_MODELS_URL}?{urlencode(params)}"


def _gemini_models_http_json(
    url: str,
    secret: str,
    *,
    opener: Callable[..., object] | None = None,
) -> object:
    if (
        not isinstance(secret, str)
        or not 1 <= len(secret.encode("utf-8")) <= MAX_PROVIDER_RESPONSE_BYTES
    ):
        raise FleetRunnerError("secret_invalid")
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "x-goog-api-key": secret,
        },
        method="GET",
    )
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
        if not isinstance(status, int):
            raise FleetRunnerError("provider_unavailable")
        if 300 <= status < 400:
            raise _RedirectRejected("redirect_rejected")
        if not 200 <= status < 300:
            try:
                raw = _provider_json_body(
                    response, url, max_bytes=MAX_GEMINI_MODELS_RESPONSE_BYTES
                )
            except _RedirectRejected:
                raise
            except FleetRunnerError:
                raw = None
            http_class: ProbeHttpClass = "5xx" if 500 <= status < 600 else "4xx"
            raise _GeminiHttpFailure(_gemini_http_error(status, raw), http_class)
        return _provider_json_body(
            response, url, max_bytes=MAX_GEMINI_MODELS_RESPONSE_BYTES
        )
    except _RedirectRejected:
        raise
    except FleetRunnerError:
        raise
    except HTTPError as exc:
        response = exc
        if 300 <= exc.code < 400:
            raise _RedirectRejected("redirect_rejected") from None
        try:
            raw = _provider_json_body(
                exc, url, max_bytes=MAX_GEMINI_MODELS_RESPONSE_BYTES
            )
        except _RedirectRejected:
            raise
        except FleetRunnerError:
            raw = None
        http_class = "5xx" if 500 <= exc.code < 600 else "4xx"
        raise _GeminiHttpFailure(
            _gemini_http_error(exc.code, raw), http_class
        ) from None
    except (OSError, URLError, TimeoutError, ValueError, TypeError):
        raise FleetRunnerError("provider_unavailable") from None
    finally:
        close = getattr(response, "close", None)
        if callable(close):
            close()


def _gemini_models_page(raw: object) -> tuple[list[object], str | None]:
    if not isinstance(raw, Mapping):
        raise FleetRunnerError("provider_response_invalid")
    models = raw.get("models")
    if not isinstance(models, list):
        raise FleetRunnerError("provider_response_invalid")
    if len(models) > MAX_GEMINI_MODELS_PAGE_SIZE:
        raise FleetRunnerError("provider_model_limit_exceeded")
    token = raw.get("nextPageToken")
    if token is not None and not isinstance(token, str):
        raise FleetRunnerError("provider_response_invalid")
    if isinstance(token, str) and token == "":
        token = None
    if token is not None:
        _gemini_models_page_url(token)
    return models, token


def _gemini_generation_methods(item: Mapping[str, object]) -> tuple[str, ...]:
    raw_methods = item.get("supportedGenerationMethods")
    if not isinstance(raw_methods, list):
        return ()
    methods: list[str] = []
    for method in raw_methods:
        if (
            isinstance(method, str)
            and method in _GEMINI_GENERATION_METHODS
            and method not in methods
        ):
            methods.append(method)
    return tuple(methods)


def _gemini_model_result(raw_models: Iterable[object]) -> dict[str, dict[str, object]]:
    models: dict[str, dict[str, object]] = {}
    for item in raw_models:
        if not isinstance(item, Mapping):
            continue
        raw_name = item.get("name", item.get("id", item.get("model")))
        if not isinstance(raw_name, str):
            continue
        if raw_name.startswith("models/"):
            raw_name = raw_name[len("models/") :]
        try:
            model_id = validate_gemini_probe_model(raw_name)
        except FleetRunnerError:
            continue
        methods = list(_gemini_generation_methods(item))
        existing = models.get(model_id)
        if existing is not None:
            methods = list(existing["supported_generation_methods"]) + [
                method
                for method in methods
                if method not in existing["supported_generation_methods"]
            ]
        supports_generate_content = "generateContent" in methods
        models[model_id] = {
            "id": model_id,
            "supported_generation_methods": methods,
            "supports_generate_content": supports_generate_content,
            "agentic": supports_generate_content,
            "readiness_worker": supports_generate_content,
        }
        if len(models) > MAX_GEMINI_MODELS:
            raise FleetRunnerError("provider_model_limit_exceeded")
    return models


def probe_gemini_models(
    secret: str | None,
    *,
    opener: Callable[..., object] | None = None,
) -> ProviderModelsResult:
    if secret is None:
        return ProviderModelsResult(Provider.GEMINI_API, False, (), "secret_missing")
    try:
        page_token: str | None = None
        seen_tokens: set[str] = set()
        raw_models_all: list[object] = []
        for _page_number in range(MAX_GEMINI_MODELS_PAGES):
            raw = _gemini_models_http_json(
                _gemini_models_page_url(page_token),
                secret,
                opener=opener,
            )
            raw_models, next_token = _gemini_models_page(raw)
            raw_models_all.extend(raw_models)
            if len(raw_models_all) > MAX_GEMINI_MODELS:
                raise FleetRunnerError("provider_model_limit_exceeded")
            if next_token is None:
                break
            if next_token in seen_tokens:
                raise FleetRunnerError("provider_response_invalid")
            seen_tokens.add(next_token)
            page_token = next_token
        else:
            raise FleetRunnerError("provider_model_limit_exceeded")
        projected = _gemini_model_result(raw_models_all)
    except _GeminiHttpFailure as exc:
        return ProviderModelsResult(
            Provider.GEMINI_API,
            False,
            (),
            exc.code,
            exc.error,
            exc.http_class,
        )
    except _RedirectRejected as exc:
        return ProviderModelsResult(
            Provider.GEMINI_API,
            False,
            (),
            exc.code,
            None,
            "transport",
        )
    except FleetRunnerError as exc:
        return ProviderModelsResult(Provider.GEMINI_API, False, (), exc.code)
    return ProviderModelsResult(
        Provider.GEMINI_API, True, tuple(projected.values()), None
    )


def _gemini_http_error(status: int, raw: object) -> ProviderError:
    payload = _mapping(raw)
    details = _mapping(payload.get("error")) if payload is not None else None
    code = details.get("code") if details is not None else None
    status_name = details.get("status") if details is not None else None
    code = code if isinstance(code, str) else ""
    status_name = status_name if isinstance(status_name, str) else ""

    if 500 <= status < 600:
        return ProviderError(
            "provider_unavailable",
            True,
            None,
            None,
            diagnostic_code="gemini_probe_generate_content_http_5xx_provider_unavailable",
        )
    if (
        status == 429
        or code in {"rate_limit_exceeded", "quota_exceeded"}
        or status_name
        in {
            "RESOURCE_EXHAUSTED",
            "BUDGET_EXHAUSTED",
            "ADMINISTRATIVE_QUOTA_LOCKED",
        }
    ):
        quota_observation = _quota_observation(details) if details is not None else None
        return ProviderError(
            "account_limited",
            True,
            None,
            None,
            quota_observation,
            "gemini_probe_generate_content_http_4xx_rate_or_quota_exhausted",
        )
    if status == 401 or code == "authentication" or status_name == "UNAUTHENTICATED":
        return ProviderError(
            "auth_invalid",
            False,
            None,
            None,
            diagnostic_code="gemini_probe_generate_content_http_4xx_authentication",
        )
    if (
        status == 403
        or code == "permission_denied"
        or status_name == "PERMISSION_DENIED"
    ):
        return ProviderError(
            "auth_or_billing_denied",
            False,
            None,
            None,
            diagnostic_code="gemini_probe_generate_content_http_4xx_auth_or_billing_denied",
        )
    if code == "model_not_found" or status_name == "MODEL_NOT_FOUND":
        return ProviderError(
            "model_unavailable",
            False,
            None,
            None,
            diagnostic_code="gemini_probe_generate_content_http_4xx_model_not_found",
        )
    if code == "not_found" or status_name == "NOT_FOUND":
        return ProviderError(
            "runner_failed",
            False,
            None,
            None,
            diagnostic_code="gemini_probe_generate_content_http_4xx_not_found_unclassified",
        )
    if (
        code in {"invalid_request", "parameter_unknown"}
        or status_name == "INVALID_ARGUMENT"
    ):
        return ProviderError(
            "runner_failed",
            False,
            None,
            None,
            diagnostic_code="gemini_probe_generate_content_http_4xx_contract_rejected",
        )
    return ProviderError(
        "runner_failed",
        False,
        None,
        None,
        diagnostic_code="gemini_probe_generate_content_http_4xx_client_rejected_unknown",
    )


def _gemini_generate_content_response_valid(raw: object) -> bool:
    if not isinstance(raw, Mapping):
        return False
    candidates = raw.get("candidates")
    if isinstance(candidates, list) and 1 <= len(candidates) <= 8:
        return all(isinstance(candidate, Mapping) for candidate in candidates)
    return isinstance(raw.get("promptFeedback"), Mapping)


def probe_gemini_rest(
    secret: str,
    *,
    model: str | None = None,
    opener: Callable[..., object] | None = None,
) -> ProbeResult:
    """Run one capability-checked, bounded Gemini GenerateContent readiness probe."""

    try:
        model = validate_gemini_probe_model(model)
    except FleetRunnerError:
        return ProbeResult(
            Provider.GEMINI_API,
            False,
            None,
            False,
            ProviderError("model_unavailable", False, None, None),
            endpoint_role="generate_content",
        )
    if (
        not isinstance(secret, str)
        or not 1 <= len(secret.encode("utf-8")) <= MAX_PROVIDER_RESPONSE_BYTES
    ):
        return ProbeResult(
            Provider.GEMINI_API,
            False,
            model,
            False,
            ProviderError("auth_invalid", False, None, None),
            endpoint_role="generate_content",
        )

    catalog = probe_gemini_models(secret, opener=opener)
    if not catalog.available:
        if catalog.provider_error is not None:
            error = catalog.provider_error
            http_class = catalog.http_class
        elif catalog.error in {"auth_invalid", "secret_invalid", "secret_missing"}:
            error = ProviderError(
                "auth_invalid",
                False,
                None,
                None,
                diagnostic_code="gemini_probe_generate_content_http_4xx_authentication",
            )
            http_class: ProbeHttpClass | None = "4xx"
        elif catalog.error == "auth_or_billing_denied":
            error = ProviderError(
                "auth_or_billing_denied",
                False,
                None,
                None,
                diagnostic_code="gemini_probe_generate_content_http_4xx_auth_or_billing_denied",
            )
            http_class = "4xx"
        elif catalog.error == "account_limited":
            error = ProviderError(
                "account_limited",
                True,
                None,
                None,
                diagnostic_code="gemini_probe_generate_content_http_4xx_rate_or_quota_exhausted",
            )
            http_class = "4xx"
        elif catalog.error == "model_unavailable":
            error = ProviderError(
                "model_unavailable",
                False,
                None,
                None,
                diagnostic_code="gemini_probe_generate_content_http_4xx_model_not_found",
            )
            http_class = "4xx"
        elif catalog.error == "runner_failed":
            error = ProviderError("runner_failed", False, None, None)
            http_class = None
        elif catalog.error == "redirect_rejected":
            error = ProviderError(
                "provider_unavailable",
                True,
                None,
                None,
                diagnostic_code="gemini_probe_generate_content_redirect_rejected",
            )
            http_class = "transport"
        elif catalog.error in {
            "provider_unavailable",
            "provider_response_invalid",
            "provider_response_too_large",
            "provider_model_limit_exceeded",
        }:
            error = ProviderError(
                "provider_unavailable",
                True,
                None,
                None,
                diagnostic_code="gemini_probe_generate_content_transport",
            )
            http_class = "transport"
        else:
            error = ProviderError("runner_failed", False, None, None)
            http_class = None
        return ProbeResult(
            Provider.GEMINI_API,
            False,
            model,
            False,
            error,
            endpoint_role="generate_content",
            http_class=http_class,
        )

    metadata = next((item for item in catalog.models if item.get("id") == model), None)
    if metadata is None:
        return ProbeResult(
            Provider.GEMINI_API,
            False,
            model,
            False,
            ProviderError(
                "model_unavailable",
                False,
                None,
                None,
                diagnostic_code="gemini_probe_generate_content_capability_model_missing",
            ),
            endpoint_role="generate_content",
        )
    methods = metadata.get("supported_generation_methods")
    if not isinstance(methods, list) or "generateContent" not in methods:
        return ProbeResult(
            Provider.GEMINI_API,
            False,
            model,
            False,
            ProviderError(
                "model_unavailable",
                False,
                None,
                None,
                diagnostic_code="gemini_probe_generate_content_capability_method_missing",
            ),
            endpoint_role="generate_content",
        )

    body = json.dumps(
        {
            "contents": [{"role": "user", "parts": [{"text": "ping"}]}],
            "generationConfig": {"maxOutputTokens": 1},
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(body) > MAX_GEMINI_PROBE_REQUEST_BYTES:
        return ProbeResult(
            Provider.GEMINI_API,
            False,
            model,
            False,
            ProviderError("runner_failed", False, None, None),
            endpoint_role="generate_content",
        )

    content_url = f"{GEMINI_MODELS_URL}/{quote(model, safe='')}:generateContent"
    request = Request(
        content_url,
        data=body,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "x-goog-api-key": secret,
        },
        method="POST",
    )
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
        if not isinstance(status, int):
            raise FleetRunnerError("provider_unavailable")
        if 300 <= status < 400:
            raise _RedirectRejected("redirect_rejected")
        if not 200 <= status < 300:
            try:
                raw = _provider_json_body(
                    response,
                    content_url,
                    max_bytes=MAX_GEMINI_PROBE_RESPONSE_BYTES,
                )
            except _RedirectRejected:
                raise
            except FleetRunnerError:
                raw = None
            error = _gemini_http_error(status, raw)
            http_class = "5xx" if 500 <= status < 600 else "4xx"
            return ProbeResult(
                Provider.GEMINI_API,
                False,
                model,
                False,
                error,
                endpoint_role="generate_content",
                http_class=http_class,
            )
        try:
            raw = _provider_json_body(
                response, content_url, max_bytes=MAX_GEMINI_PROBE_RESPONSE_BYTES
            )
        except _RedirectRejected:
            raise
        except FleetRunnerError:
            raw = None
        if not _gemini_generate_content_response_valid(raw):
            return ProbeResult(
                Provider.GEMINI_API,
                False,
                model,
                False,
                ProviderError(
                    "provider_unavailable",
                    True,
                    None,
                    None,
                    diagnostic_code="gemini_probe_generate_content_http_2xx_json_invalid",
                ),
                endpoint_role="generate_content",
                http_class="2xx",
            )
        return ProbeResult(
            Provider.GEMINI_API,
            True,
            model,
            True,
            None,
            endpoint_role="generate_content",
            http_class="2xx",
        )
    except HTTPError as exc:
        response = exc
        try:
            raw = _provider_json_body(
                exc, content_url, max_bytes=MAX_GEMINI_PROBE_RESPONSE_BYTES
            )
        except _RedirectRejected:
            return ProbeResult(
                Provider.GEMINI_API,
                False,
                model,
                False,
                ProviderError(
                    "provider_unavailable",
                    True,
                    None,
                    None,
                    diagnostic_code="gemini_probe_generate_content_redirect_rejected",
                ),
                endpoint_role="generate_content",
                http_class="transport",
            )
        except FleetRunnerError:
            raw = None
        error = _gemini_http_error(exc.code, raw)
        http_class = "5xx" if 500 <= exc.code < 600 else "4xx"
        return ProbeResult(
            Provider.GEMINI_API,
            False,
            model,
            False,
            error,
            endpoint_role="generate_content",
            http_class=http_class,
        )
    except _RedirectRejected:
        return ProbeResult(
            Provider.GEMINI_API,
            False,
            model,
            False,
            ProviderError(
                "provider_unavailable",
                True,
                None,
                None,
                diagnostic_code="gemini_probe_generate_content_redirect_rejected",
            ),
            endpoint_role="generate_content",
            http_class="transport",
        )
    except FleetRunnerError as exc:
        if exc.code == "account_limited":
            error = ProviderError("account_limited", True, None, None)
            http_class = None
        elif exc.code in {"auth_invalid", "secret_invalid", "secret_missing"}:
            error = ProviderError("auth_invalid", False, None, None)
            http_class = None
        elif exc.code == "auth_or_billing_denied":
            error = ProviderError("auth_or_billing_denied", False, None, None)
            http_class = None
        elif exc.code in {"model_unavailable", "gemini_model_invalid"}:
            error = ProviderError("model_unavailable", False, None, None)
            http_class = None
        elif exc.code == "provider_unavailable":
            error = ProviderError(
                "provider_unavailable",
                True,
                None,
                None,
                diagnostic_code="gemini_probe_generate_content_transport",
            )
            http_class = "transport"
        else:
            error = ProviderError("runner_failed", False, None, None)
            http_class = None
        return ProbeResult(
            Provider.GEMINI_API,
            False,
            model,
            False,
            error,
            endpoint_role="generate_content",
            http_class=http_class,
        )
    except (OSError, URLError, TimeoutError, ValueError, TypeError):
        return ProbeResult(
            Provider.GEMINI_API,
            False,
            model,
            False,
            ProviderError(
                "provider_unavailable",
                True,
                None,
                None,
                diagnostic_code="gemini_probe_generate_content_transport",
            ),
            endpoint_role="generate_content",
            http_class="transport",
        )
    finally:
        close = getattr(response, "close", None)
        if callable(close):
            close()


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
    settings_path.write_text(
        json.dumps(settings, sort_keys=True) + "\n", encoding="utf-8"
    )
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

    if (
        not isinstance(secret, str)
        or not 1 <= len(secret.encode("utf-8")) <= MAX_PROVIDER_RESPONSE_BYTES
    ):
        return ProbeResult(
            Provider.GEMINI_API,
            False,
            None,
            False,
            ProviderError("auth_invalid", False, None, None),
        )
    process_phase: ProbeProcessPhase | None = None
    process_output_shape: ProbeOutputShape | None = None
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
        if exc.code == "model_unavailable":
            kind = "model_unavailable"
            diagnostic_code: ProbeDiagnosticCode | None = None
            process_phase = None
        else:
            kind = "provider_unavailable"
            diagnostic_code = "gemini_probe_runner_failure"
            process_phase = "gemini_probe_runner_not_started_or_failed"
        return ProbeResult(
            Provider.GEMINI_API,
            False,
            None,
            False,
            ProviderError(
                kind,
                False,
                None,
                None,
                diagnostic_code=diagnostic_code,
            ),
            process_phase=process_phase,
        )
    probe_home_path: Path | None = None
    env: dict[str, str] = {}
    result = None
    registry = HeadlessJobRegistry()
    job = HeadlessJob(
        "gemini-provider-probe", "provider-probe", None, time.monotonic(), 0
    )
    try:
        with tempfile.TemporaryDirectory(
            prefix="codex-master-gemini-probe-"
        ) as temporary_root:
            probe_home_path = Path(temporary_root)
            probe_home_path.chmod(0o700)
            _gemini_probe_settings(probe_home_path)
            for name in ("PATH", "LANG", "LC_ALL", "TZ", "TERM"):
                value = os.environ.get(name)
                if value:
                    env[name] = value
            env.update(
                {
                    "HOME": str(probe_home_path),
                    "GEMINI_CLI_HOME": str(probe_home_path),
                    "GEMINI_API_KEY": secret,
                    "GEMINI_CLI_TRUST_WORKSPACE": "true",
                }
            )
            argv = [
                command,
                "--output-format",
                "stream-json",
                "--prompt",
                "",
                "--approval-mode=plan",
                "--skip-trust",
                "--model",
                model or GEMINI_DEFAULT_LIGHT_MODEL,
            ]
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
    except HeadlessJobError as exc:
        process_phase = (
            "gemini_probe_process_group_unreaped"
            if getattr(exc, "code", None) == "headless_process_unreaped"
            else "gemini_probe_runner_not_started_or_failed"
        )
        return ProbeResult(
            Provider.GEMINI_API,
            False,
            None,
            False,
            ProviderError(
                "runner_failed",
                False,
                None,
                None,
                diagnostic_code="gemini_probe_runner_failure",
            ),
            process_phase=process_phase,
        )
    except Exception:
        process_phase = "gemini_probe_runner_not_started_or_failed"
        return ProbeResult(
            Provider.GEMINI_API,
            False,
            None,
            False,
            ProviderError(
                "provider_unavailable",
                True,
                None,
                None,
                diagnostic_code="gemini_probe_runner_failure",
            ),
            process_phase=process_phase,
        )
    finally:
        env.pop("GEMINI_API_KEY", None)
        env.clear()
        if result is not None:
            registry.finish(job, result)

    if result.timed_out:
        process_output_shape: ProbeOutputShape | None = None
        process_stdout_shape = None
        process_stdout_event_class = None
        process_stdout_error_seen: bool | None = None
        stdout_error: FleetRunnerError | None = None
        stdout_event_class: ProbeStdoutEventClass | None = None
        stdout_error_seen = None
        if result.stdout:
            try:
                stdout_lines = result.stdout.decode("utf-8").splitlines()
            except UnicodeDecodeError:
                stdout_error = FleetRunnerError("invalid_gemini_jsonl")
            else:
                _, stdout_error, stdout_event_class, stdout_error_seen = (
                    _scan_gemini_jsonl(stdout_lines)
                )
            if not result.readers_alive and not result.stdout_truncated:
                if stdout_error is None:
                    process_stdout_shape = "gemini_probe_stdout_terminal_jsonl"
                else:
                    process_stdout_shape = (
                        "gemini_probe_stdout_jsonl_incomplete"
                        if getattr(stdout_error, "code", None)
                        == "gemini_result_missing"
                        else "gemini_probe_stdout_unclassified"
                    )
                if (
                    process_stdout_shape == "gemini_probe_stdout_jsonl_incomplete"
                    and isinstance(stdout_event_class, str)
                    and isinstance(stdout_error_seen, bool)
                ):
                    process_stdout_event_class = stdout_event_class
                    process_stdout_error_seen = stdout_error_seen
            else:
                process_stdout_shape = None
        if result.readers_alive or result.stdout_truncated or result.stderr_truncated:
            process_output_shape = "gemini_probe_output_truncated_or_pipe_open"
        elif result.stdout == b"" and result.stderr == b"":
            process_output_shape = "gemini_probe_output_none"
        elif result.stderr == b"" and result.stdout != b"":
            if stdout_error is None:
                process_output_shape = "gemini_probe_output_stdout_terminal"
            elif getattr(stdout_error, "code", None) == "gemini_result_missing":
                process_output_shape = "gemini_probe_output_stdout_jsonl_incomplete"
            else:
                process_output_shape = "gemini_probe_output_stdout_unclassified"
        elif result.stdout == b"" and result.stderr != b"":
            process_output_shape = "gemini_probe_output_stderr_only"
        elif result.stdout != b"" and result.stderr != b"":
            process_output_shape = "gemini_probe_output_stdout_stderr"

        if result.stdout == b"" and result.stderr == b"":
            process_phase = "gemini_probe_timeout_no_output"
        elif result.stderr == b"" and result.stdout != b"":
            if stdout_error is None:
                process_phase = "gemini_probe_timeout_output_unclassified"
            elif getattr(stdout_error, "code", None) == "gemini_result_missing":
                process_phase = "gemini_probe_timeout_structured_no_terminal"
            else:
                process_phase = "gemini_probe_timeout_output_unclassified"
        elif result.stdout == b"" and result.stderr != b"":
            process_phase = "gemini_probe_timeout_output_unclassified"
        elif result.stdout != b"" and result.stderr != b"":
            process_phase = "gemini_probe_timeout_output_unclassified"
        else:
            process_phase = "gemini_probe_timeout_output_unclassified"
        return ProbeResult(
            Provider.GEMINI_API,
            False,
            None,
            False,
            ProviderError(
                "provider_unavailable",
                True,
                None,
                None,
                diagnostic_code="gemini_probe_process_timeout",
            ),
            process_phase=process_phase,
            process_output_shape=process_output_shape,
            process_stdout_shape=process_stdout_shape,
            process_stdout_event_class=process_stdout_event_class,
            process_stdout_error_seen=process_stdout_error_seen,
        )

    if (
        not result.cancelled
        and result.returncode == 0
        and not result.readers_alive
        and not result.stdout_truncated
        and not result.stderr_truncated
    ):
        process_phase = "gemini_probe_normal_exit"
    elif result.readers_alive:
        process_phase = "gemini_probe_exit_output_pipe_open"
    elif result.returncode != 0:
        process_phase = "gemini_probe_exit_nonzero"
    else:
        process_phase = None

    try:
        parsed = parse_gemini_jsonl(result.stdout.decode("utf-8").splitlines())
    except (FleetRunnerError, UnicodeDecodeError):
        return ProbeResult(
            Provider.GEMINI_API,
            False,
            None,
            False,
            ProviderError(
                "runner_failed",
                False,
                None,
                None,
                diagnostic_code="gemini_probe_jsonl_terminal_invalid",
            ),
            process_phase=process_phase,
        )
    if parsed.error is not None:
        parsed_error = parsed.error
        parsed_diagnostic_code: str | None = None
        if parsed_error.kind in {"provider_unavailable", "runner_failed"}:
            parsed_diagnostic_code = "gemini_probe_structured_response"
        return ProbeResult(
            Provider.GEMINI_API,
            False,
            parsed.model,
            False,
            ProviderError(
                parsed_error.kind,
                parsed_error.retryable,
                parsed_error.status_code,
                parsed_error.reset_at_utc,
                quota_observation=parsed_error.quota_observation,
                diagnostic_code=parsed_diagnostic_code,
            ),
            process_phase=process_phase,
        )
    if result.returncode != 0 or result.stdout_truncated or result.stderr_truncated:
        return ProbeResult(
            Provider.GEMINI_API,
            False,
            parsed.model,
            False,
            ProviderError(
                "runner_failed",
                False,
                None,
                None,
                diagnostic_code="gemini_probe_runner_failure",
            ),
            process_phase=process_phase,
        )
    if not isinstance(parsed.model, str) or not parsed.model:
        return ProbeResult(
            Provider.GEMINI_API,
            False,
            None,
            False,
            ProviderError("model_unavailable", False, None, None),
            process_phase=process_phase,
        )
    return ProbeResult(
        Provider.GEMINI_API, True, parsed.model, True, None, process_phase=process_phase
    )


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
    if provider is Provider.GEMINI_API:
        return probe_gemini_models(secret, opener=opener)
    return ProviderModelsResult(provider, False, (), "unsupported_provider")
