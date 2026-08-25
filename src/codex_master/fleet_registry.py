from __future__ import annotations

import json
import re
from uuid import UUID
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any
from unicodedata import category

from codex_master.agent_resolver import (
    LEADERSHIP_CLASS_IDS,
    ResolutionDecision,
    SelectionOffer,
    SelectionOption,
    canonical_resolution_decision_digest,
    validate_resolution_decision_offer,
)
from codex_master.worker_resolution_carrier import (
    WorkerRegistryReservationV2,
    WorkerResolutionCarrierV2,
    WorkerResolutionEvidenceV2,
)
from codex_master.worker_spawn_ledger import FenceEpoch, Generation

MAX_DOCUMENT_BYTES = 1024 * 1024
MAX_ACCOUNTS = 64
MAX_SERIES = 64
MAX_RUNTIME_PRINCIPALS = 64
MAX_AGENTS = 1000
MAX_SERIES_COUNT = 100
MAX_GENERATION = 2**63 - 1
_ACCOUNT_ID_RE = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_LIMIT_REASON_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_PROFILE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_CREDENTIAL_BINDING_HMAC_RE = re.compile(r"hmac-sha256:[0-9a-f]{64}\Z")
_RUNTIME_PRINCIPAL_ID_RE = re.compile(r"tl-[0-9a-f]{32}\Z")
_DYNAMIC_WORKER_PRINCIPAL_ID_RE = re.compile(r"dw-[0-9a-f]{32}\Z")
_SHA256_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
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
    # Gemini quotas are project-scoped, while spend/tier caps may be shared
    # by a billing account.  Keep that distinction in the registry instead
    # of deriving it from a display name forever.
    billing_group: str | None = None


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
    skill_profile: str = "generic"
    task_profile: str = "standard"


@dataclass(frozen=True, slots=True)
class LegacyFleetSeriesMember:
    migration_identity: str
    ordinal: int
    account_id: str | None
    enabled: bool
    model_override: str | None = None
    skill_profile_override: str | None = None
    task_profile_override: str | None = None


@dataclass(frozen=True, slots=True)
class FleetMigrationSeries:
    prefix: str
    display_name: str
    runner: RunnerKind
    provider: Provider
    model: str
    enabled: bool
    skill_profile: str
    task_profile: str
    members: tuple[LegacyFleetSeriesMember, ...]


@dataclass(frozen=True, slots=True)
class FleetMigrationSnapshot:
    source_schema_version: int
    generation: int
    accounts: tuple[FleetAccount, ...]
    series: tuple[FleetMigrationSeries, ...]


@dataclass(frozen=True, slots=True)
class FleetAccountV2:
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
    billing_group: str | None = None
    credential_binding_id: str | None = None

    def __repr__(self) -> str:
        return "FleetAccountV2(<redacted>)"

    def __str__(self) -> str:
        return repr(self)


@dataclass(frozen=True, slots=True)
class FleetSeriesMember:
    member_id: str
    ordinal: int
    account_id: str | None
    enabled: bool
    model_override: str | None = None
    skill_profile_override: str | None = None
    task_profile_override: str | None = None

    def __repr__(self) -> str:
        return "FleetSeriesMember(<redacted>)"

    def __str__(self) -> str:
        return repr(self)


@dataclass(frozen=True, slots=True)
class FleetSeriesV2:
    prefix: str
    display_name: str
    runner: RunnerKind
    provider: Provider
    model: str
    enabled: bool
    skill_profile: str
    task_profile: str
    members: tuple[FleetSeriesMember, ...]

    @property
    def count(self) -> int:
        return len(self.members)


@dataclass(frozen=True, slots=True)
class FleetRuntimePrincipalV2:
    principal_id: str
    account_id: str
    profile_id: str
    credential_binding_id: str
    class_id: str
    lifecycle: str
    provider: Provider
    runner: RunnerKind
    model: str
    reasoning: str
    enabled: bool

    def __repr__(self) -> str:
        return "FleetRuntimePrincipalV2(<redacted>)"

    def __str__(self) -> str:
        return repr(self)


@dataclass(frozen=True, slots=True)
class FleetDynamicWorkerPrincipalV2:
    principal_id: str
    ticket_id: str
    ticket_ledger_revision: int
    ticket_fence_epoch: int
    ticket_resolution_generation: int
    ticket_policy_digest: str
    ticket_policy_generation: int
    capability_binding_digest: str
    resolution_decision_digest: str
    resolver_offer_generation: str
    lease_binding_digest: str
    class_id: str
    lifecycle: str
    model: str
    reasoning: str
    enabled: bool
    resolution_evidence: WorkerResolutionEvidenceV2
    reservation_lease_binding_digest: str | None
    reservation_account_binding_digest: str | None
    reservation_profile_binding_digest: str | None

    def __repr__(self) -> str:
        return "FleetDynamicWorkerPrincipalV2(<redacted>)"

    def __str__(self) -> str:
        return repr(self)


@dataclass(frozen=True, slots=True)
class FleetSnapshotV2:
    schema_version: int
    generation: int
    accounts: tuple[FleetAccountV2, ...]
    series: tuple[FleetSeriesV2, ...]
    runtime_principals: tuple[
        FleetRuntimePrincipalV2 | FleetDynamicWorkerPrincipalV2, ...
    ]

    def __post_init__(self) -> None:
        object.__setattr__(self, "accounts", tuple(self.accounts))
        object.__setattr__(self, "series", tuple(self.series))
        object.__setattr__(self, "runtime_principals", tuple(self.runtime_principals))

    def __repr__(self) -> str:
        return "FleetSnapshotV2(<redacted>)"

    def __str__(self) -> str:
        return repr(self)


@dataclass(frozen=True, slots=True)
class FleetSnapshot:
    schema_version: int
    generation: int
    accounts: tuple[FleetAccount, ...]
    series: tuple[FleetSeries, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "accounts", tuple(self.accounts))
        object.__setattr__(self, "series", tuple(self.series))


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
    runner_path: Path | None = None
    skill_profile: str = "generic"
    task_profile: str = "standard"


@dataclass(frozen=True, slots=True)
class InventorySnapshot:
    agent_ids: tuple[str, ...]
    agents: Mapping[str, AgentDescriptor]
    by_series: Mapping[str, tuple[str, ...]]
    positions: Mapping[str, int]
    series_prefixes: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "agent_ids", tuple(self.agent_ids))
        object.__setattr__(self, "agents", MappingProxyType(dict(self.agents)))
        object.__setattr__(self, "by_series", MappingProxyType({key: tuple(value) for key, value in self.by_series.items()}))
        object.__setattr__(self, "positions", MappingProxyType(dict(self.positions)))
        object.__setattr__(self, "series_prefixes", tuple(self.series_prefixes))


_PROVIDER_RULES = {
    Provider.OPENAI_CHATGPT: (RunnerKind.CODEX_CLI, AuthKind.CHATGPT_SESSION, True),
    Provider.OPENAI_API: (RunnerKind.CODEX_CLI, AuthKind.API_KEY, True),
    Provider.GEMINI_API: (RunnerKind.GEMINI_CLI, AuthKind.API_KEY, True),
    Provider.OLLAMA_LOCAL: (RunnerKind.CODEX_CLI, AuthKind.NONE, False),
    Provider.HUGGINGFACE_INFERENCE: (RunnerKind.CODEX_CLI, AuthKind.API_KEY, True),
}
_V1_ROOT_FIELDS = frozenset({"schema_version", "generation", "accounts", "series"})
_V2_ROOT_FIELDS = frozenset({"schema_version", "generation", "accounts", "series", "runtime_principals"})
_ACCOUNT_FIELDS = frozenset({
    "account_id", "label", "provider", "auth_kind", "secret_state", "limit_state",
    "enabled", "reset_at_utc", "last_probe_at_utc", "limit_reason", "billing_group",
    "credential_binding_id",
})
_SERIES_FIELDS = frozenset({
    "prefix", "display_name", "count", "runner", "provider", "model", "account_id", "enabled",
    "skill_profile", "task_profile",
})
_V2_SERIES_FIELDS = frozenset({
    "prefix", "display_name", "runner", "provider", "model", "enabled",
    "skill_profile", "task_profile", "members",
})
_MEMBER_FIELDS = frozenset({
    "member_id", "ordinal", "account_id", "enabled", "model_override",
    "skill_profile_override", "task_profile_override",
})
_RUNTIME_PRINCIPAL_FIELDS = frozenset({
    "principal_id", "account_id", "profile_id", "credential_binding_id", "class_id",
    "lifecycle", "provider", "runner", "model", "reasoning", "enabled",
})
_DYNAMIC_WORKER_PRINCIPAL_FIELDS = frozenset(
    {
        "principal_id",
        "ticket_id",
        "ticket_ledger_revision",
        "ticket_fence_epoch",
        "ticket_resolution_generation",
        "ticket_policy_digest",
        "ticket_policy_generation",
        "capability_binding_digest",
        "resolution_decision_digest",
        "resolver_offer_generation",
        "lease_binding_digest",
        "class_id",
        "lifecycle",
        "model",
        "reasoning",
        "enabled",
        "resolution_evidence",
        "reservation_lease_binding_digest",
        "reservation_account_binding_digest",
        "reservation_profile_binding_digest",
    }
)
_WORKER_RESOLUTION_EVIDENCE_FIELDS = frozenset(
    {
        "decision",
        "offer",
        "offer_generation",
        "capability_binding_digest",
        "resolution_generation",
        "policy_digest",
        "policy_generation",
        "ticket_fence_epoch",
    }
)
_RESOLUTION_DECISION_FIELDS = frozenset(
    {
        "class_id",
        "lifecycle",
        "model",
        "reasoning",
        "reason_codes",
        "fallback",
        "requested_class",
        "requested_lifecycle",
        "requested_model",
        "requested_reasoning",
    }
)
_SELECTION_OFFER_FIELDS = frozenset(
    {
        "generation",
        "classes",
        "lifecycles",
        "models",
        "reasoning_levels",
        "options",
    }
)
_SELECTION_OPTION_FIELDS = frozenset(
    {"class_id", "lifecycle", "model", "reasoning"}
)


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
    if any(category(character) == "Cc" for character in value):
        _fail(code)
    return value


def _boolean(value: object, code: str) -> bool:
    if not isinstance(value, bool):
        _fail(code)
    return value


def _worker_counter(value: object, code: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_GENERATION:
        _fail(code)
    return value


def _sha256_digest(value: object, code: str) -> str:
    digest = _text(value, minimum=71, maximum=71, code=code)
    if not _SHA256_DIGEST_RE.fullmatch(digest):
        _fail(code)
    return digest


def _optional_sha256_digest(value: object, code: str) -> str | None:
    if value is None:
        return None
    return _sha256_digest(value, code)


def _resolution_decision(value: object, code: str) -> ResolutionDecision:
    raw = _mapping(value, code)
    if set(raw) != _RESOLUTION_DECISION_FIELDS:
        _fail(code)
    reason_codes = raw["reason_codes"]
    if not isinstance(reason_codes, list):
        _fail(code)
    return ResolutionDecision(
        class_id=raw["class_id"],  # type: ignore[arg-type]
        lifecycle=raw["lifecycle"],  # type: ignore[arg-type]
        model=raw["model"],  # type: ignore[arg-type]
        reasoning=raw["reasoning"],  # type: ignore[arg-type]
        reason_codes=tuple(reason_codes),
        fallback=raw["fallback"],  # type: ignore[arg-type]
        requested_class=raw["requested_class"],  # type: ignore[arg-type]
        requested_lifecycle=raw["requested_lifecycle"],  # type: ignore[arg-type]
        requested_model=raw["requested_model"],  # type: ignore[arg-type]
        requested_reasoning=raw["requested_reasoning"],  # type: ignore[arg-type]
    )


def _selection_offer(value: object, code: str) -> SelectionOffer:
    raw = _mapping(value, code)
    if set(raw) != _SELECTION_OFFER_FIELDS:
        _fail(code)
    sequence_fields = ("classes", "lifecycles", "models", "reasoning_levels")
    if any(not isinstance(raw[field], list) for field in sequence_fields):
        _fail(code)
    options_raw = raw["options"]
    if not isinstance(options_raw, list):
        _fail(code)
    options: list[SelectionOption] = []
    for value in options_raw:
        option = _mapping(value, code)
        if set(option) != _SELECTION_OPTION_FIELDS:
            _fail(code)
        options.append(
            SelectionOption(
                class_id=option["class_id"],  # type: ignore[arg-type]
                lifecycle=option["lifecycle"],  # type: ignore[arg-type]
                model=option["model"],  # type: ignore[arg-type]
                reasoning=option["reasoning"],  # type: ignore[arg-type]
            )
        )
    return SelectionOffer(
        generation=raw["generation"],  # type: ignore[arg-type]
        classes=tuple(raw["classes"]),  # type: ignore[arg-type]
        lifecycles=tuple(raw["lifecycles"]),  # type: ignore[arg-type]
        models=tuple(raw["models"]),  # type: ignore[arg-type]
        reasoning_levels=tuple(raw["reasoning_levels"]),  # type: ignore[arg-type]
        options=tuple(options),
    )


def _worker_resolution_evidence(
    value: object, code: str
) -> WorkerResolutionEvidenceV2:
    raw = _mapping(value, code)
    if set(raw) != _WORKER_RESOLUTION_EVIDENCE_FIELDS:
        _fail(code)
    decision = _resolution_decision(raw["decision"], code)
    offer = _selection_offer(raw["offer"], code)
    offer_generation = _sha256_digest(raw["offer_generation"], code)
    try:
        validate_resolution_decision_offer(decision, offer)
    except ValueError:
        _fail(code)
    if offer_generation != offer.generation:
        _fail(code)
    return WorkerResolutionEvidenceV2(
        decision=decision,
        offer=offer,
        offer_generation=offer_generation,
        capability_binding_digest=_sha256_digest(
            raw["capability_binding_digest"], code
        ),
        resolution_generation=Generation(
            _worker_counter(raw["resolution_generation"], code)
        ),
        policy_digest=_sha256_digest(raw["policy_digest"], code),
        policy_generation=Generation(
            _worker_counter(raw["policy_generation"], code)
        ),
        ticket_fence_epoch=FenceEpoch(
            _worker_counter(raw["ticket_fence_epoch"], code)
        ),
    )


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


def _binding_id(value: object, *, code: str, require_hmac: bool) -> str | None:
    if value is None:
        return None
    text = _text(value, minimum=1, maximum=200, code=code)
    if require_hmac and not _CREDENTIAL_BINDING_HMAC_RE.fullmatch(text):
        _fail(code)
    return text


def _account(value: object, *, v2: bool = False) -> FleetAccount | FleetAccountV2:
    code = "invalid_account"
    raw = _mapping(value, code)
    if set(raw) - _ACCOUNT_FIELDS or (not v2 and "credential_binding_id" in raw):
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
    billing_group = raw.get("billing_group")
    if billing_group is not None:
        billing_group = _text(billing_group, minimum=1, maximum=64, code=code)
        if not _ACCOUNT_ID_RE.fullmatch(billing_group):
            _fail(code)
    credential_binding_id = _binding_id(
        raw.get("credential_binding_id"),
        code=code,
        require_hmac=v2 and provider is Provider.OPENAI_CHATGPT,
    )
    if v2:
        return FleetAccountV2(
            account_id, _text(raw["label"], minimum=1, maximum=120, code=code), provider, auth_kind,
            secret_state, _enum(LimitState, raw.get("limit_state", "unknown"), code),
            _boolean(raw["enabled"], code), _time(raw.get("reset_at_utc"), code),
            _time(raw.get("last_probe_at_utc"), code), _optional_reason(raw.get("limit_reason"), code),
            billing_group, credential_binding_id,
        )
    return FleetAccount(
        account_id, _text(raw["label"], minimum=1, maximum=120, code=code), provider, auth_kind,
        secret_state, _enum(LimitState, raw.get("limit_state", "unknown"), code),
        _boolean(raw["enabled"], code), _time(raw.get("reset_at_utc"), code),
        _time(raw.get("last_probe_at_utc"), code), _optional_reason(raw.get("limit_reason"), code),
        billing_group
    )


def _series(value: object) -> FleetSeries:
    code = "invalid_series"
    raw = _mapping(value, code)
    required = {"prefix", "display_name", "count", "runner", "provider", "model", "account_id", "enabled"}
    if set(raw) - _SERIES_FIELDS or not required.issubset(raw):
        _fail(code)
    prefix = _text(raw["prefix"], minimum=1, maximum=16, code=code)
    # Keep the original one-letter form; multi-part prefixes use an explicit
    # separator so agent ids remain unambiguous (for example ``o-a1``).
    if not re.fullmatch(r"[a-z](?:[a-z0-9_-]*[-_][a-z0-9_-]*)?", prefix):
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
        _text(raw.get("skill_profile", "generic"), minimum=1, maximum=64, code=code),
        _text(raw.get("task_profile", "standard"), minimum=1, maximum=64, code=code),
    )


def _optional_override(value: object, code: str) -> str | None:
    if value is None:
        return None
    return _text(value, minimum=1, maximum=200, code=code)


def _member(value: object) -> FleetSeriesMember:
    code = "invalid_member"
    raw = _mapping(value, code)
    if set(raw) - _MEMBER_FIELDS or not {"member_id", "ordinal", "account_id", "enabled"}.issubset(raw):
        _fail(code)
    member_id = raw["member_id"]
    if not isinstance(member_id, str):
        _fail(code)
    try:
        parsed = UUID(member_id)
    except (ValueError, AttributeError):
        _fail(code)
    if parsed.version != 4 or str(parsed) != member_id:
        _fail(code)
    ordinal = raw["ordinal"]
    if isinstance(ordinal, bool) or not isinstance(ordinal, int) or ordinal < 1:
        _fail(code)
    account_id = raw["account_id"]
    if account_id is not None:
        account_id = _text(account_id, minimum=1, maximum=64, code=code)
        if not _ACCOUNT_ID_RE.fullmatch(account_id):
            _fail(code)
    return FleetSeriesMember(
        member_id, ordinal, account_id, _boolean(raw["enabled"], code),
        _optional_override(raw.get("model_override"), code),
        _optional_override(raw.get("skill_profile_override"), code),
        _optional_override(raw.get("task_profile_override"), code),
    )


def _series_v2(value: object) -> FleetSeriesV2:
    code = "invalid_series"
    raw = _mapping(value, code)
    required = {"prefix", "display_name", "runner", "provider", "model", "enabled", "members"}
    if set(raw) - _V2_SERIES_FIELDS or not required.issubset(raw):
        _fail(code)
    prefix = _text(raw["prefix"], minimum=1, maximum=16, code=code)
    if not re.fullmatch(r"[a-z](?:[a-z0-9_-]*[-_][a-z0-9_-]*)?", prefix):
        _fail(code)
    provider = _enum(Provider, raw["provider"], code)
    runner = _enum(RunnerKind, raw["runner"], code)
    if runner is not _PROVIDER_RULES[provider][0]:
        _fail(code)
    if provider is Provider.GEMINI_API and prefix != "g":
        _fail(code)
    if prefix == "g" and provider is not Provider.GEMINI_API:
        _fail(code)
    members_raw = raw["members"]
    if not isinstance(members_raw, list) or not members_raw or len(members_raw) > MAX_SERIES_COUNT:
        _fail(code)
    members = tuple(sorted((_member(item) for item in members_raw), key=lambda member: member.ordinal))
    return FleetSeriesV2(
        prefix, _text(raw["display_name"], minimum=1, maximum=120, code=code), runner, provider,
        _text(raw["model"], minimum=1, maximum=200, code=code), _boolean(raw["enabled"], code),
        _text(raw.get("skill_profile", "generic"), minimum=1, maximum=64, code=code),
        _text(raw.get("task_profile", "standard"), minimum=1, maximum=64, code=code), members,
    )


def _dynamic_worker_principal(
    value: Mapping[str, object],
) -> FleetDynamicWorkerPrincipalV2:
    code = "invalid_runtime_principal"
    if set(
        value
    ) - _DYNAMIC_WORKER_PRINCIPAL_FIELDS or _DYNAMIC_WORKER_PRINCIPAL_FIELDS - set(
        value
    ):
        _fail(code)
    principal_id = _text(value["principal_id"], minimum=35, maximum=35, code=code)
    if not _DYNAMIC_WORKER_PRINCIPAL_ID_RE.fullmatch(principal_id):
        _fail(code)
    ticket_id = _text(value["ticket_id"], minimum=1, maximum=256, code=code)
    digest_fields = (
        "ticket_policy_digest",
        "capability_binding_digest",
        "resolution_decision_digest",
        "resolver_offer_generation",
        "lease_binding_digest",
    )
    digests: dict[str, str] = {}
    for field in digest_fields:
        digests[field] = _sha256_digest(value[field], code)
    counter_fields = (
        "ticket_ledger_revision", "ticket_fence_epoch", "ticket_resolution_generation",
        "ticket_policy_generation",
    )
    counters: dict[str, int] = {}
    for field in counter_fields:
        counters[field] = _worker_counter(value[field], code)
    evidence = _worker_resolution_evidence(value["resolution_evidence"], code)
    class_id = _text(value["class_id"], minimum=1, maximum=128, code=code)
    lifecycle = _text(value["lifecycle"], minimum=1, maximum=32, code=code)
    model = _text(value["model"], minimum=1, maximum=200, code=code)
    reasoning = _text(value["reasoning"], minimum=1, maximum=32, code=code)
    if (
        canonical_resolution_decision_digest(evidence.decision)
        != digests["resolution_decision_digest"]
        or evidence.capability_binding_digest
        != digests["capability_binding_digest"]
        or evidence.resolution_generation.value
        != counters["ticket_resolution_generation"]
        or evidence.policy_digest != digests["ticket_policy_digest"]
        or evidence.policy_generation.value != counters["ticket_policy_generation"]
        or evidence.ticket_fence_epoch.value != counters["ticket_fence_epoch"]
        or evidence.offer_generation != digests["resolver_offer_generation"]
        or (
            class_id,
            lifecycle,
            model,
            reasoning,
        )
        != (
            evidence.decision.class_id,
            evidence.decision.lifecycle,
            evidence.decision.model,
            evidence.decision.reasoning,
        )
        or evidence.decision.class_id in LEADERSHIP_CLASS_IDS
    ):
        _fail(code)
    return FleetDynamicWorkerPrincipalV2(
        principal_id=principal_id,
        ticket_id=ticket_id,
        ticket_ledger_revision=counters["ticket_ledger_revision"],
        ticket_fence_epoch=counters["ticket_fence_epoch"],
        ticket_resolution_generation=counters["ticket_resolution_generation"],
        ticket_policy_digest=digests["ticket_policy_digest"],
        ticket_policy_generation=counters["ticket_policy_generation"],
        capability_binding_digest=digests["capability_binding_digest"],
        resolution_decision_digest=digests["resolution_decision_digest"],
        resolver_offer_generation=digests["resolver_offer_generation"],
        lease_binding_digest=digests["lease_binding_digest"],
        class_id=class_id,
        lifecycle=lifecycle,
        model=model,
        reasoning=reasoning,
        enabled=_boolean(value["enabled"], code),
        resolution_evidence=evidence,
        reservation_lease_binding_digest=_optional_sha256_digest(
            value["reservation_lease_binding_digest"], code
        ),
        reservation_account_binding_digest=_optional_sha256_digest(
            value["reservation_account_binding_digest"], code
        ),
        reservation_profile_binding_digest=_optional_sha256_digest(
            value["reservation_profile_binding_digest"], code
        ),
    )


def _runtime_principal(
    value: object,
) -> FleetRuntimePrincipalV2 | FleetDynamicWorkerPrincipalV2:
    code = "invalid_runtime_principal"
    raw = _mapping(value, code)
    principal_id = raw.get("principal_id")
    if isinstance(principal_id, str) and _DYNAMIC_WORKER_PRINCIPAL_ID_RE.fullmatch(
        principal_id
    ):
        return _dynamic_worker_principal(raw)
    if set(raw) - _RUNTIME_PRINCIPAL_FIELDS or _RUNTIME_PRINCIPAL_FIELDS - set(raw):
        _fail(code)
    principal_id = _text(raw["principal_id"], minimum=1, maximum=35, code=code)
    if not _RUNTIME_PRINCIPAL_ID_RE.fullmatch(principal_id):
        _fail(code)
    account_id = _text(raw["account_id"], minimum=1, maximum=64, code=code)
    if not _ACCOUNT_ID_RE.fullmatch(account_id):
        _fail(code)
    profile_id = _text(raw["profile_id"], minimum=1, maximum=128, code=code)
    if not _PROFILE_ID_RE.fullmatch(profile_id):
        _fail(code)
    credential_binding_id = _binding_id(raw["credential_binding_id"], code=code, require_hmac=True)
    if credential_binding_id is None:
        _fail(code)
    return FleetRuntimePrincipalV2(
        principal_id=principal_id,
        account_id=account_id,
        profile_id=profile_id,
        credential_binding_id=credential_binding_id,
        class_id=_exact_text(raw["class_id"], expected="teamleiterin", code=code),
        lifecycle=_exact_text(raw["lifecycle"], expected="persistent", code=code),
        provider=_exact_enum(Provider, raw["provider"], expected=Provider.OPENAI_CHATGPT, code=code),
        runner=_exact_enum(RunnerKind, raw["runner"], expected=RunnerKind.CODEX_CLI, code=code),
        model=_exact_text(raw["model"], expected="gpt-5.6-terra", code=code),
        reasoning=_exact_text(raw["reasoning"], expected="xhigh", code=code),
        enabled=_boolean(raw["enabled"], code),
    )


def _exact_text(value: object, *, expected: str, code: str) -> str:
    text = _text(value, minimum=1, maximum=max(1, len(expected)), code=code)
    if text != expected:
        _fail(code)
    return text


def _exact_enum(enum: type[Enum], value: object, *, expected: Enum, code: str) -> Any:
    resolved = _enum(enum, value, code)
    if resolved is not expected:
        _fail(code)
    return resolved


def normalize_fleet_document(raw: object) -> FleetSnapshot | FleetSnapshotV2:
    try:
        encoded = json.dumps(raw, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        encoded_bytes = encoded.encode("utf-8")
    except (TypeError, UnicodeEncodeError, ValueError):
        _fail("invalid_document")
    if len(encoded_bytes) > MAX_DOCUMENT_BYTES:
        _fail("invalid_document")
    document = _mapping(raw, "invalid_document")
    if document.get("schema_version") not in (1, 2):
        _fail("invalid_document")
    is_v2 = document.get("schema_version") == 2
    if set(document) != (_V2_ROOT_FIELDS if is_v2 else _V1_ROOT_FIELDS):
        _fail("invalid_document")
    generation = document.get("generation")
    if (
        isinstance(generation, bool)
        or not isinstance(generation, int)
        or not 0 <= generation <= MAX_GENERATION
    ):
        _fail("invalid_document")
    accounts_raw = document.get("accounts")
    series_raw = document.get("series")
    if not isinstance(accounts_raw, list) or not isinstance(series_raw, list):
        _fail("invalid_document")
    if len(accounts_raw) > MAX_ACCOUNTS or len(series_raw) > MAX_SERIES:
        _fail("invalid_document")
    accounts = tuple(sorted((_account(item, v2=is_v2) for item in accounts_raw), key=lambda item: item.account_id))
    series = tuple(sorted(((_series_v2(item) if is_v2 else _series(item)) for item in series_raw), key=lambda item: item.prefix))
    runtime_principals_raw = document.get("runtime_principals", [])
    if not isinstance(runtime_principals_raw, list):
        _fail("invalid_document")
    if len(runtime_principals_raw) > MAX_RUNTIME_PRINCIPALS:
        _fail("invalid_document")
    runtime_principals = tuple(
        sorted((_runtime_principal(item) for item in runtime_principals_raw), key=lambda item: item.principal_id)
    )
    if len({item.account_id for item in accounts}) != len(accounts):
        _fail("invalid_account")
    if len({item.prefix for item in series}) != len(series):
        # Older callers used the former 26-series cap and report an oversized
        # document when that legacy shape contains repeated alphabetic ids.
        _fail("invalid_document" if len(series) > 26 else "invalid_series")
    if sum(item.count for item in series) > MAX_AGENTS:
        _fail("invalid_document")
    accounts_by_id = {item.account_id: item for item in accounts}
    all_member_ids: set[str] = set()
    for item in series:
        if is_v2:
            member_ids = [member.member_id for member in item.members]
            if (len(set(member_ids)) != len(member_ids) or all_member_ids.intersection(member_ids)
                    or [m.ordinal for m in item.members] != list(range(1, item.count + 1))):
                _fail("invalid_member")
            all_member_ids.update(member_ids)
            for member in item.members:
                account = accounts_by_id.get(member.account_id) if member.account_id is not None else None
                requires_account = _PROVIDER_RULES[item.provider][2]
                if (requires_account and (member.account_id is None or account is None)) or (
                        account is not None and account.provider is not item.provider):
                    _fail("invalid_member")
                if member.enabled and (not item.enabled or (account is not None and not account.enabled)):
                    _fail("invalid_member")
        elif item.account_id is not None:
            account = accounts_by_id.get(item.account_id)
            if account is None or account.provider is not item.provider:
                _fail("invalid_series")
    if is_v2:
        if len({item.principal_id for item in runtime_principals}) != len(runtime_principals):
            _fail("invalid_runtime_principal")
        dynamic_workers = tuple(
            item
            for item in runtime_principals
            if isinstance(item, FleetDynamicWorkerPrincipalV2)
        )
        if (
            len({item.ticket_id for item in dynamic_workers})
            != len(dynamic_workers)
            or len({item.lease_binding_digest for item in dynamic_workers})
            != len(dynamic_workers)
        ):
            _fail("invalid_runtime_principal")
        bindings = [
            account.credential_binding_id
            for account in accounts
            if account.enabled and account.credential_binding_id is not None
        ]
        if len(bindings) != len(set(bindings)):
            _fail("duplicate_credential_binding")
        for principal in runtime_principals:
            if isinstance(principal, FleetDynamicWorkerPrincipalV2):
                continue
            account = accounts_by_id.get(principal.account_id)
            if (
                account is None
                or account.provider is not Provider.OPENAI_CHATGPT
                or account.auth_kind is not AuthKind.CHATGPT_SESSION
                or account.credential_binding_id != principal.credential_binding_id
            ):
                _fail("invalid_runtime_principal")
            if not principal.enabled:
                continue
            if (
                not account.enabled
                or account.secret_state is not SecretState.CONFIGURED
                or account.limit_state is not LimitState.READY
            ):
                _fail("invalid_runtime_principal")
        return FleetSnapshotV2(2, generation, accounts, series, runtime_principals)
    return FleetSnapshot(1, generation, accounts, series)


def _resolution_evidence_document(
    evidence: WorkerResolutionEvidenceV2,
) -> dict[str, object]:
    return {
        "decision": {
            "class_id": evidence.decision.class_id,
            "lifecycle": evidence.decision.lifecycle,
            "model": evidence.decision.model,
            "reasoning": evidence.decision.reasoning,
            "reason_codes": list(evidence.decision.reason_codes),
            "fallback": evidence.decision.fallback,
            "requested_class": evidence.decision.requested_class,
            "requested_lifecycle": evidence.decision.requested_lifecycle,
            "requested_model": evidence.decision.requested_model,
            "requested_reasoning": evidence.decision.requested_reasoning,
        },
        "offer": {
            "generation": evidence.offer.generation,
            "classes": list(evidence.offer.classes),
            "lifecycles": list(evidence.offer.lifecycles),
            "models": list(evidence.offer.models),
            "reasoning_levels": list(evidence.offer.reasoning_levels),
            "options": [
                {
                    "class_id": option.class_id,
                    "lifecycle": option.lifecycle,
                    "model": option.model,
                    "reasoning": option.reasoning,
                }
                for option in evidence.offer.options
            ],
        },
        "offer_generation": evidence.offer_generation,
        "capability_binding_digest": evidence.capability_binding_digest,
        "resolution_generation": evidence.resolution_generation.value,
        "policy_digest": evidence.policy_digest,
        "policy_generation": evidence.policy_generation.value,
        "ticket_fence_epoch": evidence.ticket_fence_epoch.value,
    }


def fleet_document(snapshot: FleetSnapshot | FleetSnapshotV2 | FleetMigrationSnapshot) -> dict[str, object]:
    if isinstance(snapshot, FleetMigrationSnapshot):
        _fail("final_member_id_required")
    if isinstance(snapshot, FleetSnapshotV2):
        for series in snapshot.series:
            for member in series.members:
                if not _is_canonical_uuid4(member.member_id):
                    _fail("final_member_id_required")
        return {
            "schema_version": 2, "generation": snapshot.generation,
            "accounts": [
                {"account_id": item.account_id, "label": item.label, "provider": item.provider.value,
                 "auth_kind": item.auth_kind.value, "secret_state": item.secret_state.value,
                 "limit_state": item.limit_state.value, "enabled": item.enabled,
                 "reset_at_utc": item.reset_at_utc, "last_probe_at_utc": item.last_probe_at_utc,
                 "limit_reason": item.limit_reason, "billing_group": item.billing_group,
                 "credential_binding_id": item.credential_binding_id}
                for item in snapshot.accounts
            ],
            "series": [
                {"prefix": item.prefix, "display_name": item.display_name, "runner": item.runner.value,
                 "provider": item.provider.value, "model": item.model, "enabled": item.enabled,
                 "skill_profile": item.skill_profile, "task_profile": item.task_profile,
                 "members": [
                     {"member_id": member.member_id, "ordinal": member.ordinal,
                      "account_id": member.account_id, "enabled": member.enabled,
                      "model_override": member.model_override,
                      "skill_profile_override": member.skill_profile_override,
                      "task_profile_override": member.task_profile_override}
                     for member in item.members
                ]}
                for item in snapshot.series
            ],
            "runtime_principals": [
                (
                    {
                        "principal_id": item.principal_id,
                        "account_id": item.account_id,
                        "profile_id": item.profile_id,
                        "credential_binding_id": item.credential_binding_id,
                        "class_id": item.class_id,
                        "lifecycle": item.lifecycle,
                        "provider": item.provider.value,
                        "runner": item.runner.value,
                        "model": item.model,
                        "reasoning": item.reasoning,
                        "enabled": item.enabled,
                    }
                    if isinstance(item, FleetRuntimePrincipalV2)
                    else {
                        "principal_id": item.principal_id,
                        "ticket_id": item.ticket_id,
                        "ticket_ledger_revision": item.ticket_ledger_revision,
                        "ticket_fence_epoch": item.ticket_fence_epoch,
                        "ticket_resolution_generation": item.ticket_resolution_generation,
                        "ticket_policy_digest": item.ticket_policy_digest,
                        "ticket_policy_generation": item.ticket_policy_generation,
                        "capability_binding_digest": item.capability_binding_digest,
                        "resolution_decision_digest": item.resolution_decision_digest,
                        "resolver_offer_generation": item.resolver_offer_generation,
                        "lease_binding_digest": item.lease_binding_digest,
                        "class_id": item.class_id,
                        "lifecycle": item.lifecycle,
                        "model": item.model,
                        "reasoning": item.reasoning,
                        "enabled": item.enabled,
                        "resolution_evidence": _resolution_evidence_document(
                            item.resolution_evidence
                        ),
                        "reservation_lease_binding_digest": (
                            item.reservation_lease_binding_digest
                        ),
                        "reservation_account_binding_digest": (
                            item.reservation_account_binding_digest
                        ),
                        "reservation_profile_binding_digest": (
                            item.reservation_profile_binding_digest
                        ),
                    }
                )
                for item in snapshot.runtime_principals
            ],
        }
    return {
        "schema_version": snapshot.schema_version,
        "generation": snapshot.generation,
        "accounts": [
            {
                "account_id": item.account_id, "label": item.label, "provider": item.provider.value,
                "auth_kind": item.auth_kind.value, "secret_state": item.secret_state.value,
                "limit_state": item.limit_state.value, "enabled": item.enabled,
                "reset_at_utc": item.reset_at_utc, "last_probe_at_utc": item.last_probe_at_utc,
                "limit_reason": item.limit_reason, "billing_group": item.billing_group,
            }
            for item in snapshot.accounts
        ],
        "series": [
            {
                "prefix": item.prefix, "display_name": item.display_name, "count": item.count,
                "runner": item.runner.value, "provider": item.provider.value, "model": item.model,
                "account_id": item.account_id, "enabled": item.enabled,
                "skill_profile": item.skill_profile, "task_profile": item.task_profile,
            }
            for item in snapshot.series
        ],
    }


def _is_canonical_uuid4(member_id: object) -> bool:
    if not isinstance(member_id, str):
        return False
    try:
        parsed = UUID(member_id)
    except (ValueError, AttributeError):
        return False
    return parsed.version == 4 and str(parsed) == member_id


def build_inventory(snapshot: FleetSnapshot | FleetSnapshotV2, pool_root: Path) -> InventorySnapshot:
    accounts = {item.account_id: item for item in snapshot.accounts}
    agents: dict[str, AgentDescriptor] = {}
    by_series: dict[str, tuple[str, ...]] = {}
    positions: dict[str, int] = {}
    agent_ids: list[str] = []
    root = Path(pool_root)
    for item in snapshot.series:
        ids: list[str] = []
        if isinstance(item, FleetSeriesV2):
            members = item.members
            series_account = None
        else:
            members = tuple(range(1, item.count + 1))
            series_account = item.account_id
        account = accounts.get(series_account) if series_account is not None else None
        for member_or_ordinal in members:
            ordinal = member_or_ordinal.ordinal if isinstance(member_or_ordinal, FleetSeriesMember) else member_or_ordinal
            member_account = member_or_ordinal.account_id if isinstance(member_or_ordinal, FleetSeriesMember) else series_account
            member_enabled = member_or_ordinal.enabled if isinstance(member_or_ordinal, FleetSeriesMember) else True
            account = accounts.get(member_account) if member_account is not None else None
            agent_id = f"{item.prefix}{ordinal}"
            ids.append(agent_id)
            agent_ids.append(agent_id)
            positions[agent_id] = len(agent_ids) - 1
            executable = "gemini" if item.runner is RunnerKind.GEMINI_CLI else "codex"
            model = member_or_ordinal.model_override or item.model if isinstance(member_or_ordinal, FleetSeriesMember) else item.model
            skill = member_or_ordinal.skill_profile_override or item.skill_profile if isinstance(member_or_ordinal, FleetSeriesMember) else item.skill_profile
            task = member_or_ordinal.task_profile_override or item.task_profile if isinstance(member_or_ordinal, FleetSeriesMember) else item.task_profile
            enabled = item.enabled and member_enabled and (account is None or account.enabled)
            agents[agent_id] = AgentDescriptor(
                agent_id, item.prefix, ordinal, f"{item.display_name} {ordinal}", item.runner,
                item.provider, model, member_account, root / agent_id,
                f"codex_agent_{agent_id}_mcp", enabled, root / agent_id / executable,
                skill, task,
            )
        by_series[f"{item.prefix}-series"] = tuple(ids)
    return InventorySnapshot(tuple(agent_ids), MappingProxyType(agents), MappingProxyType(by_series),
                             MappingProxyType(positions), tuple(item.prefix for item in snapshot.series))


def public_fleet_snapshot(snapshot: FleetSnapshot | FleetSnapshotV2) -> dict[str, object]:
    if isinstance(snapshot, FleetSnapshotV2):
        return {
            "generation": snapshot.generation, "account_count": len(snapshot.accounts),
            "series_count": len(snapshot.series), "agent_count": sum(item.count for item in snapshot.series),
            "runtime_principal_count": len(snapshot.runtime_principals),
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


def expand_v1_for_migration(snapshot: FleetSnapshot) -> FleetMigrationSnapshot:
    if not isinstance(snapshot, FleetSnapshot) or snapshot.schema_version != 1:
        _fail("invalid_document")
    series = tuple(
        FleetMigrationSeries(
            item.prefix, item.display_name, item.runner, item.provider, item.model, item.enabled,
            item.skill_profile, item.task_profile,
            tuple(LegacyFleetSeriesMember(f"v1:{item.prefix}:{ordinal}", ordinal, item.account_id, True)
                  for ordinal in range(1, item.count + 1)),
        )
        for item in snapshot.series
    )
    return FleetMigrationSnapshot(1, snapshot.generation, snapshot.accounts, series)


def _generation(snapshot: FleetSnapshot | FleetSnapshotV2, expected_generation: int) -> None:
    if (not isinstance(expected_generation, int) or isinstance(expected_generation, bool)
            or snapshot.generation != expected_generation):
        _fail("generation_conflict")


def _next(
    snapshot: FleetSnapshot | FleetSnapshotV2,
    *,
    accounts: Iterable[FleetAccount] | Iterable[FleetAccountV2] | None = None,
    series: Iterable[FleetSeries] | Iterable[FleetSeriesV2] | None = None,
    runtime_principals: Iterable[
        FleetRuntimePrincipalV2 | FleetDynamicWorkerPrincipalV2
    ]
    | None = None,
) -> FleetSnapshot | FleetSnapshotV2:
    if snapshot.generation >= MAX_GENERATION:
        _fail("invalid_document")
    if isinstance(snapshot, FleetSnapshotV2):
        candidate = FleetSnapshotV2(
            snapshot.schema_version,
            snapshot.generation + 1,
            tuple(snapshot.accounts if accounts is None else accounts),
            tuple(snapshot.series if series is None else series),
            tuple(snapshot.runtime_principals if runtime_principals is None else runtime_principals),
        )
    else:
        candidate = FleetSnapshot(
            snapshot.schema_version,
            snapshot.generation + 1,
            tuple(snapshot.accounts if accounts is None else accounts),
            tuple(snapshot.series if series is None else series),
        )
    return normalize_fleet_document(fleet_document(candidate))


def plan_account_upsert(
    snapshot: FleetSnapshot | FleetSnapshotV2,
    account: FleetAccount | FleetAccountV2,
    *,
    expected_generation: int,
) -> FleetSnapshot | FleetSnapshotV2:
    _generation(snapshot, expected_generation)
    if isinstance(snapshot, FleetSnapshotV2) is not isinstance(account, FleetAccountV2):
        _fail("invalid_account")
    accounts = [item for item in snapshot.accounts if item.account_id != account.account_id] + [account]
    return _next(snapshot, accounts=accounts)


def _dynamic_worker_from_reservation(
    reservation: object, lease_binding_digest: object
) -> FleetDynamicWorkerPrincipalV2:
    if type(reservation) is not WorkerRegistryReservationV2:
        _fail("invalid_worker_registry_reservation")
    resolution = reservation.resolution
    if type(resolution) is not WorkerResolutionCarrierV2:
        _fail("invalid_worker_registry_reservation")
    if reservation.ticket_fence_epoch != resolution.ticket_fence_epoch:
        _fail("invalid_worker_registry_reservation")
    if resolution.decision.class_id in LEADERSHIP_CLASS_IDS:
        _fail("invalid_runtime_principal")
    evidence = WorkerResolutionEvidenceV2(
        decision=resolution.decision,
        offer=resolution.offer,
        offer_generation=resolution.resolver_offer_generation,
        capability_binding_digest=resolution.capability_binding_digest,
        resolution_generation=resolution.ticket_resolution_generation,
        policy_digest=resolution.ticket_policy_digest,
        policy_generation=resolution.ticket_policy_generation,
        ticket_fence_epoch=resolution.ticket_fence_epoch,
    )
    return _dynamic_worker_principal(
        {
            "principal_id": reservation.principal_id,
            "ticket_id": resolution.ticket_id,
            "ticket_ledger_revision": reservation.ticket_ledger_revision.value,
            "ticket_fence_epoch": reservation.ticket_fence_epoch.value,
            "ticket_resolution_generation": resolution.ticket_resolution_generation.value,
            "ticket_policy_digest": resolution.ticket_policy_digest,
            "ticket_policy_generation": resolution.ticket_policy_generation.value,
            "capability_binding_digest": resolution.capability_binding_digest,
            "resolution_decision_digest": resolution.resolution_decision_digest,
            "resolver_offer_generation": resolution.resolver_offer_generation,
            "lease_binding_digest": lease_binding_digest,
            "class_id": resolution.decision.class_id,
            "lifecycle": resolution.decision.lifecycle,
            "model": resolution.decision.model,
            "reasoning": resolution.decision.reasoning,
            "enabled": True,
            "resolution_evidence": _resolution_evidence_document(evidence),
            "reservation_lease_binding_digest": reservation.lease_binding_digest,
            "reservation_account_binding_digest": reservation.account_binding_digest,
            "reservation_profile_binding_digest": reservation.profile_binding_digest,
        }
    )


def plan_dynamic_worker_principal_reserve(
    snapshot: FleetSnapshotV2,
    reservation: WorkerRegistryReservationV2,
    *,
    lease_binding_digest: object,
    expected_generation: int,
) -> FleetSnapshotV2:
    if not isinstance(snapshot, FleetSnapshotV2):
        _fail("invalid_document")
    _generation(snapshot, expected_generation)
    principal = _dynamic_worker_from_reservation(reservation, lease_binding_digest)
    workers = [
        item
        for item in snapshot.runtime_principals
        if isinstance(item, FleetDynamicWorkerPrincipalV2)
    ]
    if any(item.principal_id == principal.principal_id for item in workers):
        _fail("worker_principal_collision")
    if any(item.ticket_id == principal.ticket_id for item in workers):
        _fail("worker_ticket_collision")
    if any(
        item.lease_binding_digest == principal.lease_binding_digest for item in workers
    ):
        _fail("worker_lease_collision")
    return _next(
        snapshot,
        runtime_principals=[*snapshot.runtime_principals, principal],
    )  # type: ignore[return-value]


def plan_dynamic_worker_principal_release(
    snapshot: FleetSnapshotV2,
    reservation: WorkerRegistryReservationV2,
    *,
    lease_binding_digest: object,
    expected_generation: int,
) -> FleetSnapshotV2:
    if not isinstance(snapshot, FleetSnapshotV2):
        _fail("invalid_document")
    _generation(snapshot, expected_generation)
    expected = _dynamic_worker_from_reservation(reservation, lease_binding_digest)
    existing = next(
        (
            item
            for item in snapshot.runtime_principals
            if isinstance(item, FleetDynamicWorkerPrincipalV2)
            and item.principal_id == expected.principal_id
        ),
        None,
    )
    if existing != expected:
        _fail("worker_reservation_mismatch")
    return _next(
        snapshot,
        runtime_principals=[
            item for item in snapshot.runtime_principals if item != expected
        ],
    )  # type: ignore[return-value]


def plan_runtime_principal_upsert(
    snapshot: FleetSnapshotV2,
    principal: FleetRuntimePrincipalV2,
    *,
    expected_generation: int,
) -> FleetSnapshotV2:
    if not isinstance(snapshot, FleetSnapshotV2):
        _fail("invalid_document")
    if not isinstance(principal, FleetRuntimePrincipalV2):
        _fail("invalid_runtime_principal")
    _generation(snapshot, expected_generation)
    runtime_principals = [
        item for item in snapshot.runtime_principals if item.principal_id != principal.principal_id
    ] + [principal]
    return _next(snapshot, runtime_principals=runtime_principals)  # type: ignore[return-value]


def plan_runtime_principal_disable(
    snapshot: FleetSnapshotV2,
    principal_id: str,
    *,
    expected_generation: int,
) -> FleetSnapshotV2:
    if not isinstance(snapshot, FleetSnapshotV2):
        _fail("invalid_document")
    _generation(snapshot, expected_generation)
    existing = next(
        (
            item
            for item in snapshot.runtime_principals
            if item.principal_id == principal_id
        ),
        None,
    )
    if not isinstance(existing, FleetRuntimePrincipalV2):
        _fail("invalid_runtime_principal")
    runtime_principals = [
        replace(item, enabled=False) if item.principal_id == principal_id else item
        for item in snapshot.runtime_principals
    ]
    return _next(snapshot, runtime_principals=runtime_principals)  # type: ignore[return-value]


def plan_runtime_principal_delete(
    snapshot: FleetSnapshotV2,
    principal_id: str,
    *,
    expected_generation: int,
) -> FleetSnapshotV2:
    if not isinstance(snapshot, FleetSnapshotV2):
        _fail("invalid_document")
    _generation(snapshot, expected_generation)
    existing = next((item for item in snapshot.runtime_principals if item.principal_id == principal_id), None)
    if not isinstance(existing, FleetRuntimePrincipalV2):
        _fail("invalid_runtime_principal")
    if existing.enabled:
        _fail("runtime_principal_must_be_disabled")
    runtime_principals = [item for item in snapshot.runtime_principals if item.principal_id != principal_id]
    return _next(snapshot, runtime_principals=runtime_principals)  # type: ignore[return-value]


def plan_account_disable(snapshot: FleetSnapshot, account_id: str, *, expected_generation: int) -> FleetSnapshot:
    _generation(snapshot, expected_generation)
    if not any(item.account_id == account_id for item in snapshot.accounts):
        _fail("invalid_account")
    accounts = [replace(item, enabled=False) if item.account_id == account_id else item for item in snapshot.accounts]
    return _next(snapshot, accounts=accounts)


def plan_account_delete(snapshot: FleetSnapshot, account_id: str, *, expected_generation: int) -> FleetSnapshot:
    _generation(snapshot, expected_generation)
    if any(item.account_id == account_id for item in snapshot.series):
        _fail("account_in_use")
    accounts = [item for item in snapshot.accounts if item.account_id != account_id]
    if accounts == list(snapshot.accounts):
        _fail("invalid_account")
    return _next(snapshot, accounts=accounts)


def plan_series_apply(snapshot: FleetSnapshot, series: FleetSeries, *, expected_generation: int,
                      confirmed_remove_ids: Iterable[str] = ()) -> FleetSnapshot:
    _generation(snapshot, expected_generation)
    existing = next((item for item in snapshot.series if item.prefix == series.prefix), None)
    confirmed = tuple(confirmed_remove_ids)
    if existing is not None and series.count < existing.count:
        expected = frozenset(f"{series.prefix}{number}" for number in range(series.count + 1, existing.count + 1))
        if len(confirmed) != len(expected) or frozenset(confirmed) != expected:
            _fail("remove_confirmation_required")
    elif confirmed:
        _fail("remove_confirmation_required")
    items = [item for item in snapshot.series if item.prefix != series.prefix] + [series]
    return _next(snapshot, series=items)


def plan_series_disable(snapshot: FleetSnapshot, prefix: str, *, expected_generation: int) -> FleetSnapshot:
    _generation(snapshot, expected_generation)
    if not any(item.prefix == prefix for item in snapshot.series):
        _fail("invalid_series")
    series = [replace(item, enabled=False) if item.prefix == prefix else item for item in snapshot.series]
    return _next(snapshot, series=series)


def plan_series_delete(snapshot: FleetSnapshot, prefix: str, *, expected_generation: int) -> FleetSnapshot:
    _generation(snapshot, expected_generation)
    existing = next((item for item in snapshot.series if item.prefix == prefix), None)
    if existing is None:
        _fail("invalid_series")
    if existing.enabled:
        _fail("series_must_be_disabled")
    return _next(snapshot, series=[item for item in snapshot.series if item.prefix != prefix])


def mark_account_limit(snapshot: FleetSnapshot, account_id: str, *, reset_at_utc: str | None,
                       reason: str, expected_generation: int) -> FleetSnapshot:
    _generation(snapshot, expected_generation)
    accounts = [replace(item, limit_state=LimitState.LIMITED, reset_at_utc=reset_at_utc, limit_reason=reason)
                if item.account_id == account_id else item for item in snapshot.accounts]
    if accounts == list(snapshot.accounts):
        _fail("invalid_account")
    return _next(snapshot, accounts=accounts)
