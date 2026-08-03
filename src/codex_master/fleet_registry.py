from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any


MAX_DOCUMENT_BYTES = 1024 * 1024
MAX_ACCOUNTS = 64
MAX_SERIES = 26
MAX_AGENTS = 1000
MAX_SERIES_COUNT = 100
_ACCOUNT_ID_RE = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_LIMIT_REASON_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_RFC3339_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\Z"
)


class FleetValidationError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class Provider(str, Enum):
    OPENAI_CHATGPT = "openai_chatgpt"
    OPENAI_API = "openai_api"
    GEMINI_API = "gemini_api"
    OLLAMA_LOCAL = "ollama_local"
    HUGGINGFACE_INFERENCE = "huggingface_inference"


class RunnerKind(str, Enum):
    CODEX_CLI = "codex_cli"
    GEMINI_CLI = "gemini_cli"


class AuthKind(str, Enum):
    CHATGPT_SESSION = "chatgpt_session"
    API_KEY = "api_key"
    NONE = "none"


class SecretState(str, Enum):
    MISSING = "missing"
    CONFIGURED = "configured"
    INVALID = "invalid"
    NOT_REQUIRED = "not_required"


class LimitState(str, Enum):
    READY = "ready"
    LIMITED = "limited"
    UNKNOWN = "unknown"
    PROBING = "probing"
    DISABLED = "disabled"


@dataclass(frozen=True, slots=True)
class FleetAccount:
    account_id: str
    label: str
    provider: Provider
    auth_kind: AuthKind
    secret_state: SecretState
    limit_state: LimitState
    enabled: bool
    reset_at_utc: str | None
    last_probe_at_utc: str | None
    limit_reason: str | None


@dataclass(frozen=True, slots=True)
class FleetSeries:
    prefix: str
    display_name: str
    count: int
    runner: RunnerKind
    provider: Provider
    model: str
    account_id: str | None
    enabled: bool


@dataclass(frozen=True, slots=True)
class FleetSnapshot:
    schema_version: int
    generation: int
    accounts: tuple[FleetAccount, ...]
    series: tuple[FleetSeries, ...]


@dataclass(frozen=True, slots=True)
class AgentDescriptor:
    agent_id: str
    series_prefix: str
    ordinal: int
    label: str
    runner: RunnerKind
    provider: Provider
    model: str
    account_id: str | None
    home: Path
    session: str
    enabled: bool


@dataclass(frozen=True, slots=True)
class InventorySnapshot:
    agent_ids: tuple[str, ...]
    agents: Mapping[str, AgentDescriptor]
    by_series: Mapping[str, tuple[str, ...]]
    positions: Mapping[str, int]
    series_prefixes: tuple[str, ...]


_PROVIDER_RULES = {
    Provider.OPENAI_CHATGPT: (RunnerKind.CODEX_CLI, AuthKind.CHATGPT_SESSION, True),
    Provider.OPENAI_API: (RunnerKind.CODEX_CLI, AuthKind.API_KEY, True),
    Provider.GEMINI_API: (RunnerKind.GEMINI_CLI, AuthKind.API_KEY, True),
    Provider.OLLAMA_LOCAL: (RunnerKind.CODEX_CLI, AuthKind.NONE, False),
    Provider.HUGGINGFACE_INFERENCE: (RunnerKind.CODEX_CLI, AuthKind.API_KEY, True),
}
_ROOT_FIELDS = frozenset({"schema_version", "generation", "accounts", "series"})
_ACCOUNT_FIELDS = frozenset({
    "account_id", "label", "provider", "auth_kind", "secret_state", "limit_state",
    "enabled", "reset_at_utc", "last_probe_at_utc", "limit_reason",
})
_SERIES_FIELDS = frozenset({
    "prefix", "display_name", "count", "runner", "provider", "model", "account_id", "enabled",
})


def _fail(code: str) -> None:
    raise FleetValidationError(code)


def _mapping(value: object, code: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        _fail(code)
    return value


def _enum(enum: type[Enum], value: object, code: str) -> Any:
    if not isinstance(value, str):
        _fail(code)
    try:
        return enum(value)
    except ValueError:
        _fail(code)


def _text(value: object, *, minimum: int, maximum: int, code: str) -> str:
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        _fail(code)
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        _fail(code)
    return value


def _boolean(value: object, code: str) -> bool:
    if not isinstance(value, bool):
        _fail(code)
    return value


def _time(value: object, code: str) -> str | None:
    if value is None:
        return None
    text = _text(value, minimum=1, maximum=40, code=code)
    if not _RFC3339_RE.fullmatch(text):
        _fail(code)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        _fail(code)
    if parsed.tzinfo is None:
        _fail(code)
    return text


def _optional_reason(value: object, code: str) -> str | None:
    if value is None:
        return None
    text = _text(value, minimum=1, maximum=64, code=code)
    if not _LIMIT_REASON_RE.fullmatch(text):
        _fail(code)
    return text


def _account(value: object) -> FleetAccount:
    code = "invalid_account"
    raw = _mapping(value, code)
    if set(raw) - _ACCOUNT_FIELDS:
        _fail(code)
    required = {"account_id", "label", "provider", "auth_kind", "enabled"}
    if not required.issubset(raw):
        _fail(code)
    account_id = _text(raw["account_id"], minimum=1, maximum=64, code=code)
    if not _ACCOUNT_ID_RE.fullmatch(account_id):
        _fail(code)
    provider = _enum(Provider, raw["provider"], code)
    auth_kind = _enum(AuthKind, raw["auth_kind"], code)
    rule = _PROVIDER_RULES[provider]
    if not rule[2] or auth_kind is not rule[1]:
        _fail(code)
    secret_default = SecretState.NOT_REQUIRED if auth_kind is AuthKind.NONE else SecretState.MISSING
    secret_state = _enum(SecretState, raw.get("secret_state", secret_default.value), code)
    if (auth_kind is AuthKind.NONE) is not (secret_state is SecretState.NOT_REQUIRED):
        _fail(code)
    return FleetAccount(
        account_id, _text(raw["label"], minimum=1, maximum=120, code=code), provider, auth_kind,
        secret_state, _enum(LimitState, raw.get("limit_state", "unknown"), code),
        _boolean(raw["enabled"], code), _time(raw.get("reset_at_utc"), code),
        _time(raw.get("last_probe_at_utc"), code), _optional_reason(raw.get("limit_reason"), code),
    )


def _series(value: object) -> FleetSeries:
    code = "invalid_series"
    raw = _mapping(value, code)
    if set(raw) - _SERIES_FIELDS or not _SERIES_FIELDS.issubset(raw):
        _fail(code)
    prefix = _text(raw["prefix"], minimum=1, maximum=1, code=code)
    if prefix < "a" or prefix > "z":
        _fail(code)
    count = raw["count"]
    if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= MAX_SERIES_COUNT:
        _fail(code)
    provider = _enum(Provider, raw["provider"], code)
    runner = _enum(RunnerKind, raw["runner"], code)
    if runner is not _PROVIDER_RULES[provider][0]:
        _fail(code)
    account_id = raw["account_id"]
    if account_id is not None:
        account_id = _text(account_id, minimum=1, maximum=64, code=code)
        if not _ACCOUNT_ID_RE.fullmatch(account_id):
            _fail(code)
    if _PROVIDER_RULES[provider][2] is (account_id is None):
        _fail(code)
    return FleetSeries(
        prefix, _text(raw["display_name"], minimum=1, maximum=120, code=code), count, runner,
        provider, _text(raw["model"], minimum=1, maximum=200, code=code), account_id,
        _boolean(raw["enabled"], code),
    )


def normalize_fleet_document(raw: object) -> FleetSnapshot:
    try:
        encoded = json.dumps(raw, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError):
        _fail("invalid_document")
    if len(encoded.encode("utf-8")) > MAX_DOCUMENT_BYTES:
        _fail("invalid_document")
    document = _mapping(raw, "invalid_document")
    if set(document) != _ROOT_FIELDS or document.get("schema_version") != 1:
        _fail("invalid_document")
    generation = document.get("generation")
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 0:
        _fail("invalid_document")
    accounts_raw = document.get("accounts")
    series_raw = document.get("series")
    if not isinstance(accounts_raw, list) or not isinstance(series_raw, list):
        _fail("invalid_document")
    if len(accounts_raw) > MAX_ACCOUNTS or len(series_raw) > MAX_SERIES:
        _fail("invalid_document")
    accounts = tuple(sorted((_account(item) for item in accounts_raw), key=lambda item: item.account_id))
    series = tuple(sorted((_series(item) for item in series_raw), key=lambda item: item.prefix))
    if len({item.account_id for item in accounts}) != len(accounts):
        _fail("invalid_account")
    if len({item.prefix for item in series}) != len(series):
        _fail("invalid_series")
    if sum(item.count for item in series) > MAX_AGENTS:
        _fail("invalid_document")
    accounts_by_id = {item.account_id: item for item in accounts}
    for item in series:
        if item.account_id is not None:
            account = accounts_by_id.get(item.account_id)
            if account is None or account.provider is not item.provider:
                _fail("invalid_series")
    return FleetSnapshot(1, generation, accounts, series)


def fleet_document(snapshot: FleetSnapshot) -> dict[str, object]:
    return {
        "schema_version": snapshot.schema_version,
        "generation": snapshot.generation,
        "accounts": [
            {
                "account_id": item.account_id, "label": item.label, "provider": item.provider.value,
                "auth_kind": item.auth_kind.value, "secret_state": item.secret_state.value,
                "limit_state": item.limit_state.value, "enabled": item.enabled,
                "reset_at_utc": item.reset_at_utc, "last_probe_at_utc": item.last_probe_at_utc,
                "limit_reason": item.limit_reason,
            }
            for item in snapshot.accounts
        ],
        "series": [
            {
                "prefix": item.prefix, "display_name": item.display_name, "count": item.count,
                "runner": item.runner.value, "provider": item.provider.value, "model": item.model,
                "account_id": item.account_id, "enabled": item.enabled,
            }
            for item in snapshot.series
        ],
    }


def build_inventory(snapshot: FleetSnapshot, pool_root: Path) -> InventorySnapshot:
    accounts = {item.account_id: item for item in snapshot.accounts}
    agents: dict[str, AgentDescriptor] = {}
    by_series: dict[str, tuple[str, ...]] = {}
    positions: dict[str, int] = {}
    agent_ids: list[str] = []
    root = Path(pool_root)
    for item in snapshot.series:
        ids: list[str] = []
        account = accounts.get(item.account_id) if item.account_id is not None else None
        enabled = item.enabled and (account is None or account.enabled)
        for ordinal in range(1, item.count + 1):
            agent_id = f"{item.prefix}{ordinal}"
            ids.append(agent_id)
            agent_ids.append(agent_id)
            positions[agent_id] = len(agent_ids) - 1
            agents[agent_id] = AgentDescriptor(
                agent_id, item.prefix, ordinal, f"{item.display_name} {ordinal}", item.runner,
                item.provider, item.model, item.account_id, root / agent_id,
                f"codex_agent_{agent_id}_mcp", enabled,
            )
        by_series[f"{item.prefix}-series"] = tuple(ids)
    return InventorySnapshot(tuple(agent_ids), MappingProxyType(agents), MappingProxyType(by_series),
                             MappingProxyType(positions), tuple(item.prefix for item in snapshot.series))


def public_fleet_snapshot(snapshot: FleetSnapshot) -> dict[str, object]:
    return {
        "generation": snapshot.generation, "account_count": len(snapshot.accounts),
        "series_count": len(snapshot.series), "agent_count": sum(item.count for item in snapshot.series),
        "accounts": [
            {"label": item.label, "provider": item.provider.value, "auth_kind": item.auth_kind.value,
             "secret_state": item.secret_state.value, "limit_state": item.limit_state.value,
             "enabled": item.enabled}
            for item in snapshot.accounts
        ],
        "series": [
            {"prefix": item.prefix, "display_name": item.display_name, "count": item.count,
             "runner": item.runner.value, "provider": item.provider.value, "model": item.model,
             "enabled": item.enabled}
            for item in snapshot.series
        ],
    }


def _generation(snapshot: FleetSnapshot, expected_generation: int) -> None:
    if not isinstance(expected_generation, int) or isinstance(expected_generation, bool) or snapshot.generation != expected_generation:
        _fail("generation_conflict")


def _next(snapshot: FleetSnapshot, *, accounts: Iterable[FleetAccount] | None = None,
          series: Iterable[FleetSeries] | None = None) -> FleetSnapshot:
    candidate = FleetSnapshot(snapshot.schema_version, snapshot.generation + 1,
                              tuple(snapshot.accounts if accounts is None else accounts),
                              tuple(snapshot.series if series is None else series))
    return normalize_fleet_document(fleet_document(candidate))


def plan_account_upsert(snapshot: FleetSnapshot, account: FleetAccount, *, expected_generation: int) -> FleetSnapshot:
    _generation(snapshot, expected_generation)
    accounts = [item for item in snapshot.accounts if item.account_id != account.account_id] + [account]
    return _next(snapshot, accounts=accounts)


def plan_account_disable(snapshot: FleetSnapshot, account_id: str, *, expected_generation: int) -> FleetSnapshot:
    _generation(snapshot, expected_generation)
    accounts = [replace(item, enabled=False) if item.account_id == account_id else item for item in snapshot.accounts]
    if accounts == list(snapshot.accounts): _fail("invalid_account")
    return _next(snapshot, accounts=accounts)


def plan_account_delete(snapshot: FleetSnapshot, account_id: str, *, expected_generation: int) -> FleetSnapshot:
    _generation(snapshot, expected_generation)
    if any(item.account_id == account_id for item in snapshot.series): _fail("account_in_use")
    accounts = [item for item in snapshot.accounts if item.account_id != account_id]
    if accounts == list(snapshot.accounts): _fail("invalid_account")
    return _next(snapshot, accounts=accounts)


def plan_series_apply(snapshot: FleetSnapshot, series: FleetSeries, *, expected_generation: int,
                      confirmed_remove_ids: Iterable[str] = ()) -> FleetSnapshot:
    _generation(snapshot, expected_generation)
    existing = next((item for item in snapshot.series if item.prefix == series.prefix), None)
    confirmed = tuple(confirmed_remove_ids)
    if existing is not None and series.count < existing.count:
        expected = frozenset(f"{series.prefix}{number}" for number in range(series.count + 1, existing.count + 1))
        if len(confirmed) != len(expected) or frozenset(confirmed) != expected: _fail("remove_confirmation_required")
    elif confirmed:
        _fail("remove_confirmation_required")
    items = [item for item in snapshot.series if item.prefix != series.prefix] + [series]
    return _next(snapshot, series=items)


def plan_series_disable(snapshot: FleetSnapshot, prefix: str, *, expected_generation: int) -> FleetSnapshot:
    _generation(snapshot, expected_generation)
    series = [replace(item, enabled=False) if item.prefix == prefix else item for item in snapshot.series]
    if series == list(snapshot.series): _fail("invalid_series")
    return _next(snapshot, series=series)


def plan_series_delete(snapshot: FleetSnapshot, prefix: str, *, expected_generation: int) -> FleetSnapshot:
    _generation(snapshot, expected_generation)
    existing = next((item for item in snapshot.series if item.prefix == prefix), None)
    if existing is None: _fail("invalid_series")
    if existing.enabled: _fail("series_must_be_disabled")
    return _next(snapshot, series=[item for item in snapshot.series if item.prefix != prefix])


def mark_account_limit(snapshot: FleetSnapshot, account_id: str, *, reset_at_utc: str | None,
                       reason: str, expected_generation: int) -> FleetSnapshot:
    _generation(snapshot, expected_generation)
    accounts = [replace(item, limit_state=LimitState.LIMITED, reset_at_utc=reset_at_utc, limit_reason=reason)
                if item.account_id == account_id else item for item in snapshot.accounts]
    if accounts == list(snapshot.accounts): _fail("invalid_account")
    return _next(snapshot, accounts=accounts)
