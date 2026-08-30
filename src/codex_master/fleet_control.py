"""GTK-free, bounded view-model and argument builders for fleet controls."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Mapping


MAX_ACCOUNTS = 64
MAX_SERIES = 26
MAX_SERIES_COUNT = 100
MAX_SECRET_CHARS = 16 * 1024
MAX_MODEL_CHARS = 200
MAX_LABEL_CHARS = 120
MAX_ID_CHARS = 64
MAX_OLLAMA_MODELS = 256
MAX_OLLAMA_INSTANCES = 64
_ACCOUNT_ID_RE = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_PREFIX_RE = re.compile(r"[a-z]\Z")
_ERROR_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_CONTROL_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_CPUSET_RE = re.compile(r"[0-9]+(?:-[0-9]+)?(?:,[0-9]+(?:-[0-9]+)?)*\Z")


class FleetControlError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class FleetAccountRow:
    account_id: str
    label: str
    provider: str
    auth_kind: str
    auth_status: str
    limit_state: str
    enabled: bool
    error_code: str | None = None

    @property
    def secret_state(self) -> str:
        """Compatibility view without putting the private-field name in repr."""

        return self.auth_status


@dataclass(frozen=True, slots=True)
class FleetSeriesRow:
    prefix: str
    display_name: str
    count: int
    runner: str
    provider: str
    model: str
    account_id: str | None
    enabled: bool
    eligibility: str
    error_code: str | None = None


@dataclass(frozen=True, slots=True)
class FleetPageState:
    generation: int
    accounts: tuple[FleetAccountRow, ...]
    series: tuple[FleetSeriesRow, ...]
    error_code: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "accounts", tuple(self.accounts[:MAX_ACCOUNTS]))
        object.__setattr__(self, "series", tuple(self.series[:MAX_SERIES]))
        object.__setattr__(self, "error_code", _error(self.error_code))


@dataclass(frozen=True, slots=True)
class OllamaModelRow:
    model_ref: str
    provider_model_id: str
    installed: bool
    hive_enabled: bool
    simple_only: bool
    capabilities: tuple[str, ...]
    evidence_at_utc: str | None


@dataclass(frozen=True, slots=True)
class OllamaInstanceRow:
    instance_ref: str
    label: str
    host_ref: str
    selected_model_refs: tuple[str, ...]
    allowed_cpus: str
    cpu_quota_percent: int
    cpu_weight: int
    lifecycle_state: str
    readiness_state: str
    path_state: str


@dataclass(frozen=True, slots=True)
class OllamaPageState:
    generation: int
    models: tuple[OllamaModelRow, ...]
    instances: tuple[OllamaInstanceRow, ...]
    rejected_model_count: int = 0
    rejected_instance_count: int = 0
    error_code: str | None = None


def _mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise FleetControlError("invalid_fleet_payload")
    return value


def _text(value: object, *, maximum: int, code: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum:
        raise FleetControlError(code)
    if any(ord(character) < 32 for character in value):
        raise FleetControlError(code)
    return value


def _optional_text(value: object, *, maximum: int, code: str) -> str | None:
    if value is None:
        return None
    return _text(value, maximum=maximum, code=code)


def _bool(value: object, code: str) -> bool:
    if not isinstance(value, bool):
        raise FleetControlError(code)
    return value


def _error(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, str) and _ERROR_RE.fullmatch(value):
        return value
    return "invalid_fleet_error"


def _generation(payload: Mapping[str, object]) -> int:
    value = payload.get("generation")
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise FleetControlError("invalid_fleet_generation")
    return value


def _positive_integer(value: object, code: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 10000:
        raise FleetControlError(code)
    return value


def _token_tuple(value: object, *, maximum: int, code: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not 1 <= len(value) <= maximum:
        raise FleetControlError(code)
    result = tuple(
        _text(item, maximum=MAX_MODEL_CHARS, code=code) for item in value
    )
    if len(set(result)) != len(result):
        raise FleetControlError(code)
    return result


def _rows(payload: Mapping[str, object], key: str, maximum: int) -> list[Mapping[str, object]]:
    value = payload.get(key, [])
    if not isinstance(value, list):
        raise FleetControlError("invalid_fleet_payload")
    rows: list[Mapping[str, object]] = []
    for item in value[:maximum]:
        if isinstance(item, Mapping):
            rows.append(item)
    return rows


def _provider_rule(provider: str, runner: str, account_id: str | None, auth_kind: str | None = None) -> None:
    if provider == "ollama_local":
        if runner != "codex_cli" or account_id is not None:
            raise FleetControlError("provider_runner_account_mismatch")
        return
    if provider == "gemini_api":
        expected_runner, expected_auth = "gemini_cli", "api_key"
    elif provider == "huggingface_inference":
        expected_runner, expected_auth = "codex_cli", "api_key"
    elif provider == "openai_chatgpt":
        expected_runner, expected_auth = "codex_cli", "chatgpt_session"
    elif provider == "openai_api":
        expected_runner, expected_auth = "codex_cli", "api_key"
    else:
        raise FleetControlError("invalid_provider")
    if runner != expected_runner or account_id is None:
        raise FleetControlError("provider_runner_account_mismatch")
    if auth_kind is not None and auth_kind != expected_auth:
        raise FleetControlError("provider_auth_mismatch")


def parse_fleet_page(accounts_payload: object, series_payload: object) -> FleetPageState:
    accounts_raw = _mapping(accounts_payload)
    series_raw = _mapping(series_payload)
    generation = _generation(accounts_raw)
    if _generation(series_raw) != generation:
        return FleetPageState(generation, (), (), "generation_conflict")
    account_rows: list[FleetAccountRow] = []
    for item in _rows(accounts_raw, "accounts", MAX_ACCOUNTS):
        try:
            account_id = _text(item.get("account_id"), maximum=MAX_ID_CHARS, code="invalid_account")
            if not _ACCOUNT_ID_RE.fullmatch(account_id):
                raise FleetControlError("invalid_account")
            account_rows.append(FleetAccountRow(
                account_id,
                _text(item.get("label"), maximum=MAX_LABEL_CHARS, code="invalid_account"),
                _text(item.get("provider"), maximum=64, code="invalid_account"),
                _text(item.get("auth_kind"), maximum=64, code="invalid_account"),
                _text(item.get("secret_state"), maximum=32, code="invalid_account"),
                _text(item.get("limit_state"), maximum=32, code="invalid_account"),
                _bool(item.get("enabled"), "invalid_account"),
            ))
        except FleetControlError:
            continue
    account_ids = {row.account_id for row in account_rows}
    series_rows: list[FleetSeriesRow] = []
    for item in _rows(series_raw, "series", MAX_SERIES):
        try:
            prefix = _text(item.get("prefix"), maximum=1, code="invalid_series")
            if not _PREFIX_RE.fullmatch(prefix):
                raise FleetControlError("invalid_series")
            count = item.get("count")
            if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= MAX_SERIES_COUNT:
                raise FleetControlError("invalid_series")
            provider = _text(item.get("provider"), maximum=64, code="invalid_series")
            runner = _text(item.get("runner"), maximum=64, code="invalid_series")
            account_id = _optional_text(item.get("account_id"), maximum=MAX_ID_CHARS, code="invalid_series")
            _provider_rule(provider, runner, account_id)
            eligibility = "disabled" if item.get("enabled") is not True else (
                "eligible" if account_id is None or account_id in account_ids else "account_unavailable"
            )
            series_rows.append(FleetSeriesRow(
                prefix,
                _text(item.get("display_name"), maximum=MAX_LABEL_CHARS, code="invalid_series"),
                count,
                runner,
                provider,
                _text(item.get("model"), maximum=MAX_MODEL_CHARS, code="invalid_series"),
                account_id,
                _bool(item.get("enabled"), "invalid_series"),
                eligibility,
                _error(item.get("error_code")),
            ))
        except FleetControlError:
            continue
    return FleetPageState(generation, tuple(account_rows), tuple(series_rows))


def parse_ollama_page(
    models_payload: object, instances_payload: object
) -> OllamaPageState:
    models_raw = _mapping(models_payload)
    instances_raw = _mapping(instances_payload)
    generation = _generation(instances_raw)
    model_rows: list[OllamaModelRow] = []
    model_items = _rows(models_raw, "models", MAX_OLLAMA_MODELS)
    rejected_models = min(MAX_OLLAMA_MODELS, len(models_raw.get("models", []))) - len(model_items) if isinstance(models_raw.get("models", []), list) else 0
    for item in model_items:
        try:
            capabilities = _token_tuple(
                item.get("capabilities"), maximum=16, code="invalid_ollama_model"
            )
            model_rows.append(
                OllamaModelRow(
                    _text(item.get("ref"), maximum=128, code="invalid_ollama_model"),
                    _text(
                        item.get("provider_model_id"),
                        maximum=MAX_MODEL_CHARS,
                        code="invalid_ollama_model",
                    ),
                    _bool(item.get("installed"), "invalid_ollama_model"),
                    _bool(item.get("hive_enabled"), "invalid_ollama_model"),
                    _bool(item.get("simple_only"), "invalid_ollama_model"),
                    capabilities,
                    _optional_text(
                        item.get("evidence_at_utc"),
                        maximum=40,
                        code="invalid_ollama_model",
                    ),
                )
            )
        except FleetControlError:
            rejected_models += 1
    instance_rows: list[OllamaInstanceRow] = []
    instance_items = _rows(instances_raw, "instances", MAX_OLLAMA_INSTANCES)
    rejected_instances = min(MAX_OLLAMA_INSTANCES, len(instances_raw.get("instances", []))) - len(instance_items) if isinstance(instances_raw.get("instances", []), list) else 0
    for item in instance_items:
        try:
            allowed_cpus = _text(
                item.get("allowed_cpus"), maximum=256, code="invalid_ollama_instance"
            )
            if _CPUSET_RE.fullmatch(allowed_cpus) is None:
                raise FleetControlError("invalid_ollama_instance")
            instance_rows.append(
                OllamaInstanceRow(
                    _text(item.get("ref"), maximum=128, code="invalid_ollama_instance"),
                    _text(
                        item.get("label"),
                        maximum=MAX_LABEL_CHARS,
                        code="invalid_ollama_instance",
                    ),
                    _text(
                        item.get("host_ref"), maximum=128, code="invalid_ollama_instance"
                    ),
                    _token_tuple(
                        item.get("selected_model_refs"),
                        maximum=64,
                        code="invalid_ollama_instance",
                    ),
                    allowed_cpus,
                    _positive_integer(
                        item.get("cpu_quota_percent"), "invalid_ollama_instance"
                    ),
                    _positive_integer(
                        item.get("cpu_weight"), "invalid_ollama_instance"
                    ),
                    _text(
                        item.get("lifecycle_state"),
                        maximum=32,
                        code="invalid_ollama_instance",
                    ),
                    _text(
                        item.get("readiness_state"),
                        maximum=32,
                        code="invalid_ollama_instance",
                    ),
                    _text(
                        item.get("path_state"),
                        maximum=32,
                        code="invalid_ollama_instance",
                    ),
                )
            )
        except FleetControlError:
            rejected_instances += 1
    return OllamaPageState(
        generation,
        tuple(model_rows),
        tuple(instance_rows),
        rejected_models,
        rejected_instances,
    )


def _expected_generation(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise FleetControlError("invalid_fleet_generation")
    return value


def account_upsert_args(
    *, account_id: str, label: str, provider: str, auth_kind: str,
    enabled: bool, expected_generation: int,
) -> dict[str, object]:
    account_id = _text(account_id, maximum=MAX_ID_CHARS, code="invalid_account")
    if not _ACCOUNT_ID_RE.fullmatch(account_id):
        raise FleetControlError("invalid_account")
    _provider_rule(provider, "gemini_cli" if provider == "gemini_api" else "codex_cli", account_id, auth_kind)
    return {
        "account_id": account_id,
        "label": _text(label, maximum=MAX_LABEL_CHARS, code="invalid_account"),
        "provider": _text(provider, maximum=64, code="invalid_account"),
        "auth_kind": _text(auth_kind, maximum=64, code="invalid_account"),
        "enabled": _bool(enabled, "invalid_account"),
        "expected_generation": _expected_generation(expected_generation),
    }


def account_secret_args(*, account_id: str, secret: str, expected_generation: int) -> dict[str, object]:
    account_id = _text(account_id, maximum=MAX_ID_CHARS, code="invalid_account")
    if not _ACCOUNT_ID_RE.fullmatch(account_id):
        raise FleetControlError("invalid_account")
    _text(secret, maximum=MAX_SECRET_CHARS, code="invalid_secret")
    return {
        "account_id": account_id,
        "secret": secret,
        "expected_generation": _expected_generation(expected_generation),
    }


def _series_args(
    *, prefix: str, count: int, runner: str, provider: str, model: str,
    account_id: str | None, enabled: bool, expected_generation: int,
    confirmed_remove_ids: list[str] | tuple[str, ...] | None = None,
) -> dict[str, object]:
    prefix = _text(prefix, maximum=1, code="invalid_series")
    if not _PREFIX_RE.fullmatch(prefix):
        raise FleetControlError("invalid_series")
    if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= MAX_SERIES_COUNT:
        raise FleetControlError("invalid_series")
    model = _text(model, maximum=MAX_MODEL_CHARS, code="invalid_series")
    account_id = _optional_text(account_id, maximum=MAX_ID_CHARS, code="invalid_series")
    if account_id is not None and not _ACCOUNT_ID_RE.fullmatch(account_id):
        raise FleetControlError("invalid_series")
    provider = _text(provider, maximum=64, code="invalid_series")
    runner = _text(runner, maximum=64, code="invalid_series")
    _provider_rule(provider, runner, account_id)
    if not isinstance(confirmed_remove_ids, (list, tuple)) and confirmed_remove_ids is not None:
        raise FleetControlError("invalid_series")
    confirmed = list(confirmed_remove_ids or ())
    if len(confirmed) > MAX_SERIES_COUNT:
        raise FleetControlError("invalid_series")
    confirmed = [_text(value, maximum=MAX_ID_CHARS, code="invalid_series") for value in confirmed]
    return {
        "prefix": prefix,
        "count": count,
        "runner": runner,
        "provider": provider,
        "model": model,
        "account_id": account_id,
        "enabled": _bool(enabled, "invalid_series"),
        "expected_generation": _expected_generation(expected_generation),
        "confirmed_remove_ids": confirmed,
    }


def series_plan_args(
    *, prefix: str, count: int, runner: str, provider: str, model: str,
    account_id: str | None, enabled: bool, expected_generation: int,
    confirmed_remove_ids: list[str] | tuple[str, ...] | None = None,
) -> dict[str, object]:
    return _series_args(
        prefix=prefix, count=count, runner=runner, provider=provider, model=model,
        account_id=account_id, enabled=enabled, expected_generation=expected_generation,
        confirmed_remove_ids=confirmed_remove_ids,
    )


def series_apply_args(
    *, prefix: str, count: int, runner: str, provider: str, model: str,
    account_id: str | None, enabled: bool, expected_generation: int,
    confirmed_remove_ids: list[str] | tuple[str, ...] | None = None,
) -> dict[str, object]:
    return _series_args(
        prefix=prefix, count=count, runner=runner, provider=provider, model=model,
        account_id=account_id, enabled=enabled, expected_generation=expected_generation,
        confirmed_remove_ids=confirmed_remove_ids,
    )


def ollama_instance_plan_args(
    *,
    ref: str,
    label: str,
    host_ref: str,
    ollama_executable: str,
    models_directory: str,
    selected_model_refs: list[str] | tuple[str, ...],
    allowed_cpus: str,
    cpu_quota_percent: int,
    cpu_weight: int,
    expected_generation: int,
    idempotency_key: str,
) -> dict[str, object]:
    ref = _text(ref, maximum=128, code="invalid_ollama_instance")
    host_ref = _text(host_ref, maximum=128, code="invalid_ollama_instance")
    idempotency_key = _text(
        idempotency_key, maximum=128, code="invalid_ollama_instance"
    )
    allowed_cpus = _text(
        allowed_cpus, maximum=256, code="invalid_ollama_instance"
    )
    if (
        _CONTROL_TOKEN_RE.fullmatch(ref) is None
        or _CONTROL_TOKEN_RE.fullmatch(host_ref) is None
        or _CONTROL_TOKEN_RE.fullmatch(idempotency_key) is None
        or _CPUSET_RE.fullmatch(allowed_cpus) is None
    ):
        raise FleetControlError("invalid_ollama_instance")
    executable = _text(
        ollama_executable, maximum=1024, code="invalid_ollama_instance"
    )
    model_root = _text(
        models_directory, maximum=1024, code="invalid_ollama_instance"
    )
    if not executable.startswith("/") or not model_root.startswith("/"):
        raise FleetControlError("invalid_ollama_instance")
    return {
        "ref": ref,
        "label": _text(
            label, maximum=MAX_LABEL_CHARS, code="invalid_ollama_instance"
        ),
        "host_ref": host_ref,
        "ollama_executable": executable,
        "models_directory": model_root,
        "selected_model_refs": list(
            _token_tuple(
                selected_model_refs,
                maximum=64,
                code="invalid_ollama_instance",
            )
        ),
        "allowed_cpus": allowed_cpus,
        "cpu_quota_percent": _positive_integer(
            cpu_quota_percent, "invalid_ollama_instance"
        ),
        "cpu_weight": _positive_integer(cpu_weight, "invalid_ollama_instance"),
        "expected_generation": _expected_generation(expected_generation),
        "idempotency_key": idempotency_key,
    }
