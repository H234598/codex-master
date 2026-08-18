from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import re
import secrets
import stat
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field, replace as dataclass_replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import MappingProxyType
from typing import ContextManager, Mapping, TypeVar

from .fleet_registry import (
    FleetAccount,
    FleetAccountV2,
    FleetSeries,
    FleetSnapshot,
    FleetSnapshotV2,
    InventorySnapshot,
    LimitState,
    Provider,
    SecretState,
    build_inventory,
    fleet_document,
    mark_account_limit,
    normalize_fleet_document,
    plan_account_delete,
    plan_account_upsert,
    public_fleet_snapshot,
)
from .fleet_runners import (
    FleetRunnerError,
    ProbeDiagnosticCode,
    ProbeOutputShape,
    ProbeStdoutEventClass,
    ProbeStdoutShape,
    ProbeProcessPhase,
    ProviderErrorQuotaObservation,
    ProbeResult,
    normalize_gemini_probe_diagnostic_code,
    normalize_gemini_probe_output_shape,
    normalize_gemini_probe_stdout_event_class,
    normalize_gemini_probe_stdout_shape,
    normalize_gemini_probe_process_phase,
    validate_gemini_probe_model,
)
from .selection import (
    FairnessLedger,
    ModelRole,
    SelectionCandidate,
    SelectionPolicy,
    TaskKind,
    preview_selection,
)


MAX_REGISTRY_BYTES = 1024 * 1024
MAX_LIMIT_BYTES = 256 * 1024
MAX_RATE_LIMIT_BYTES = 256 * 1024
MAX_USAGE_BYTES = 1024 * 1024
MAX_EVENT_BYTES = 512 * 1024
MAX_SECRET_BYTES = 16 * 1024
_CREDENTIAL_BINDING_SALT_BYTES = 32
_CREDENTIAL_BINDING_DOMAIN = b"codex-master:gemini-credential-binding:v1\0"
GEMINI_MIN_REQUEST_INTERVAL_SECONDS = 60
GEMINI_TIER1_LOCAL_REQUEST_INTERVAL_SECONDS = 4
GEMINI_TIER1_SPEND_RATE_LIMIT_USD_PER_10_MINUTES = 10.0
GEMINI_TIER1_BILLING_CAP_USD_PER_MONTH = 250.0
GEMINI_QUOTA_SNAPSHOT_SOURCE = "user_supplied_ai_studio_snapshots_2026-08-11"
# The dashboard exports show different tiers for projects in the same local
# account group. Keep this project-scoped and do not infer Tier 1 from the
# account number alone.
GEMINI_PROJECT_BILLING_TIERS: dict[str, str] = {
    "the-hive-1": "tier1",
    "the-hive-2": "tier1",
    "the-hive-3": "tier0",
    "the-hive-4": "tier0",
    "the-hive-6": "tier0",
    "the-hive-10": "tier0",
}
GEMINI_QUOTA_SNAPSHOTS: dict[str, dict[str, dict[str, int]]] = {
    "tier0": {
        "gemini-3.1-flash-lite": {"rpm": 15, "tpm": 250_000, "rpd": 500},
        "gemini-3-flash": {"rpm": 5, "tpm": 250_000, "rpd": 20},
        "gemini-3.5-flash": {"rpm": 5, "tpm": 250_000, "rpd": 20},
    },
    "tier1": {
        "gemini-3.1-flash-lite": {"rpm": 4_000, "tpm": 4_000_000, "rpd": 150_000},
        "gemini-3-flash": {"rpm": 1_000, "tpm": 2_000_000, "rpd": 10_000},
        "gemini-3.5-flash": {"rpm": 1_000, "tpm": 2_000_000, "rpd": 10_000},
    },
}
# Only projects with a Rate Limit export get concrete RPM/TPM/RPD values.
# H3 and H10 have a visible free-tier label in Usage exports, but no concrete
# Rate Limit table in the supplied files, so their limits remain unknown.
GEMINI_PROJECT_QUOTA_SNAPSHOTS: dict[str, dict[str, dict[str, int]]] = {
    "the-hive-1": GEMINI_QUOTA_SNAPSHOTS["tier1"],
    "the-hive-2": GEMINI_QUOTA_SNAPSHOTS["tier1"],
    "the-hive-4": GEMINI_QUOTA_SNAPSHOTS["tier0"],
    "the-hive-6": GEMINI_QUOTA_SNAPSHOTS["tier0"],
}
GEMINI_REQUEST_LEASE_SECONDS = 120 * 60 + 60
GEMINI_INITIAL_429_COOLDOWN_SECONDS = 15 * 60
GEMINI_MAX_429_COOLDOWN_SECONDS = 24 * 60 * 60
_USAGE_QUOTA_SCOPES = frozenset({"model", "account", "unknown"})
_GEMINI_MAX_USAGE_QUOTA_RETRY_SECONDS = 3600
_ACCOUNT_ID_RE = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_LIMIT_REASON_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_T = TypeVar("_T")

GEMINI_GATE_DIAGNOSTICS: Mapping[str, Mapping[str, object]] = MappingProxyType({
    "gemini_ready": MappingProxyType({
        "severity": "info", "retryable": False, "action": "allow",
        "reason": "Gemini request admitted.",
    }),
    "gemini_local_rate_limited": MappingProxyType({
        "severity": "warning", "retryable": True, "action": "defer_until",
        "reason": "Gemini local request rate limit active.",
    }),
    "gemini_rpm_exhausted": MappingProxyType({
        "severity": "warning", "retryable": True, "action": "defer_until",
        "reason": "Known Gemini requests-per-minute limit reached.",
    }),
    "gemini_tpm_exhausted": MappingProxyType({
        "severity": "warning", "retryable": True, "action": "defer_until",
        "reason": "Known Gemini input-tokens-per-minute limit reached.",
    }),
    "gemini_rpd_exhausted": MappingProxyType({
        "severity": "warning", "retryable": True, "action": "defer_until",
        "reason": "Known Gemini requests-per-day limit reached.",
    }),
    "gemini_account_limited": MappingProxyType({
        "severity": "warning", "retryable": True, "action": "defer_until",
        "reason": "Gemini account has an active provider limit.",
    }),
    "gemini_model_limited": MappingProxyType({
        "severity": "warning", "retryable": True, "action": "defer_until",
        "reason": "Gemini model has an active provider limit.",
    }),
    "gemini_account_disabled": MappingProxyType({
        "severity": "error", "retryable": False, "action": "reject",
        "reason": "Gemini account is disabled.",
    }),
    "gemini_secret_missing": MappingProxyType({
        "severity": "error", "retryable": False, "action": "reject",
        "reason": "Gemini account credential is missing.",
    }),
    "gemini_auth_invalid": MappingProxyType({
        "severity": "error", "retryable": False, "action": "reject",
        "reason": "Gemini account authentication is invalid.",
    }),
    "gemini_provider_unavailable": MappingProxyType({
        "severity": "warning", "retryable": True, "action": "reject",
        "reason": "Gemini provider is unavailable.",
    }),
    "gemini_model_unavailable": MappingProxyType({
        "severity": "error", "retryable": False, "action": "reject",
        "reason": "Gemini model is unavailable.",
    }),
    "gemini_account_limit_unknown": MappingProxyType({
        "severity": "warning", "retryable": True, "action": "reject",
        "reason": "Gemini account limit state is unknown.",
    }),
    "gemini_credential_unverified": MappingProxyType({
        "severity": "error", "retryable": False, "action": "reject",
        "reason": "Gemini account credential cannot be verified.",
    }),
    "gemini_probe_stale": MappingProxyType({
        "severity": "warning", "retryable": True, "action": "reject",
        "reason": "Gemini account probe is stale.",
    }),
    "gemini_account_unavailable": MappingProxyType({
        "severity": "error", "retryable": False, "action": "reject",
        "reason": "Gemini account is unavailable.",
    }),
    "gemini_limits_unknown": MappingProxyType({
        "severity": "warning", "retryable": False, "action": "allow",
        "reason": "Gemini dashboard limits are unknown; only observed counters are available.",
    }),
    "gemini_gate_unknown": MappingProxyType({
        "severity": "error", "retryable": False, "action": "reject",
        "reason": "Gemini gate state is unknown.",
    }),
})
_GEMINI_LEGACY_GATE_CODES = MappingProxyType({
    "ready": "gemini_ready",
    "limit_active": "gemini_account_limited",
    "probe_stale": "gemini_probe_stale",
    "gemini_local_rate_limit": "gemini_local_rate_limited",
    "account_disabled": "gemini_account_disabled",
    "account_provider_mismatch": "gemini_account_unavailable",
    "credential_binding_unknown": "gemini_credential_unverified",
    "secret_missing": "gemini_secret_missing",
    "auth_invalid": "gemini_auth_invalid",
    "provider_unavailable": "gemini_provider_unavailable",
    "model_unavailable": "gemini_model_unavailable",
    "limit_unknown": "gemini_account_limit_unknown",
})
_GEMINI_EVENT_REASON_CODES = frozenset({
    *GEMINI_GATE_DIAGNOSTICS,
    "account_limited",
    "auth_invalid",
    "model_unavailable",
    "provider_unavailable",
    "runner_failed",
    "secret_missing",
    "limit_active",
    "ready",
})


def map_gemini_gate_code(code: str) -> str:
    """Map historical gate reasons to one stable, public diagnostic code."""

    if not isinstance(code, str):
        return "gemini_gate_unknown"
    return _GEMINI_LEGACY_GATE_CODES.get(code, code if code in GEMINI_GATE_DIAGNOSTICS else "gemini_gate_unknown")


def _redacted_gemini_event_reason(reason: str | None) -> str | None:
    if reason is None:
        return None
    return reason if reason in _GEMINI_EVENT_REASON_CODES else "runner_failed"


class FleetConflictError(ValueError):
    pass


class FleetSecretError(ValueError):
    pass


class FleetRateLimitError(ValueError):
    def __init__(self, reason: str, retry_after_seconds: int) -> None:
        super().__init__(reason)
        self.reason = reason
        self.retry_after_seconds = max(0, int(retry_after_seconds))


@dataclass(frozen=True, slots=True)
class GeminiRequestReservation:
    account_id: str
    model: str | None
    reservation_id: str
    expires_at_utc: str


@dataclass(frozen=True, slots=True)
class AccountGateDecision:
    allowed: bool
    reason: str
    account_id: str | None
    generation: int


@dataclass(frozen=True, slots=True)
class GeminiGateDecision:
    action: str
    diagnostic_code: str
    reason: str
    severity: str
    retryable: bool
    account_id: str | None
    model: str | None
    defer_until: str | None = None
    target_agent_id: str | None = None
    openai_fallback_reason: str | None = None

    def public(self) -> dict[str, object]:
        return {
            "action": self.action,
            "diagnostic_code": self.diagnostic_code,
            "reason": self.reason,
            "severity": self.severity,
            "retryable": self.retryable,
            "account_id": self.account_id,
            "model": self.model,
            "defer_until": self.defer_until,
            "next_reset_at_utc": self.defer_until,
            "target_agent_id": self.target_agent_id,
            "openai_fallback_reason": self.openai_fallback_reason,
            "raw_output": "not_returned",
        }


@dataclass(frozen=True, slots=True)
class FleetPaths:
    root: Path = field(repr=False)
    registry: Path = field(repr=False)
    secrets: Path = field(repr=False)
    limits: Path = field(repr=False)
    rate_limits: Path = field(repr=False)
    lock: Path = field(repr=False)
    recovery: Path = field(repr=False)
    mutation_lock: Path = field(repr=False)
    usage: Path = field(repr=False)
    events: Path = field(repr=False)

    @classmethod
    def from_state_root(cls, root: Path) -> FleetPaths:
        fleet_root = root / "fleet"
        return cls(
            root=fleet_root,
            registry=fleet_root / "registry.json",
            secrets=fleet_root / "secrets",
            limits=fleet_root / "limits.json",
            rate_limits=fleet_root / "rate-limits.json",
            lock=fleet_root / "registry.lock",
            recovery=fleet_root / "recovery.json",
            mutation_lock=fleet_root / "mutation.lock",
            usage=fleet_root / "usage.json",
            events=fleet_root / "events.jsonl",
        )


@dataclass(frozen=True, slots=True)
class FleetPrivateIO:
    ensure_dir: Callable[[Path], None]
    read_text: Callable[[Path, int, str], str | None]
    replace_text: Callable[[Path, str], None]
    read_bytes: Callable[[Path, int, str], bytes | None]
    replace_bytes: Callable[[Path, bytes, int], None]
    lock: Callable[[], ContextManager[None]]
    utc_now: Callable[[], datetime]
    remove_file: Callable[[Path], bool] | None = None


class FleetService:
    def __init__(
        self,
        paths: FleetPaths,
        private_io: FleetPrivateIO,
        *,
        pool_root: Path,
        probe_max_age_seconds: int = 900,
        read_only: bool = False,
    ) -> None:
        self._paths = paths
        self._io = private_io
        self._pool_root = pool_root
        if not isinstance(read_only, bool):
            raise ValueError("invalid_fleet_read_only")
        self._read_only = read_only
        if (
            isinstance(probe_max_age_seconds, bool)
            or not isinstance(probe_max_age_seconds, int)
            or not 1 <= probe_max_age_seconds <= 900
        ):
            raise ValueError("invalid_probe_max_age")
        self._probe_max_age_seconds = probe_max_age_seconds

    def _ensure_layout(self) -> None:
        self._io.ensure_dir(self._paths.root)
        self._io.ensure_dir(self._paths.secrets)

    def _load_registry(self) -> FleetSnapshot | FleetSnapshotV2:
        self._ensure_layout()
        text = self._io.read_text(
            self._paths.registry,
            MAX_REGISTRY_BYTES,
            "could_not_read_fleet_registry",
        )
        if text is None:
            return FleetSnapshot(1, 1, (), ())
        try:
            raw = json.loads(text)
        except (json.JSONDecodeError, UnicodeError) as exc:
            raise ValueError("invalid_fleet_registry") from exc
        return normalize_fleet_document(raw)

    def _write_registry(self, snapshot: FleetSnapshot | FleetSnapshotV2) -> FleetSnapshot | FleetSnapshotV2:
        document = fleet_document(snapshot)
        text = json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        self._io.replace_text(self._paths.registry, text)
        stored = self._load_registry()
        if stored != snapshot:
            raise ValueError("fleet_registry_write_verification_failed")
        return stored

    @staticmethod
    def _parse_time(value: object) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str) or not 1 <= len(value) <= 40:
            raise ValueError("invalid_fleet_limits")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("invalid_fleet_limits") from None
        if parsed.tzinfo is None:
            raise ValueError("invalid_fleet_limits")
        return value

    def _quarantine_limits(self, reason: str = "invalid_fleet_limits") -> None:
        """Record a redacted limits failure without overwriting the WAL journal."""

        marker = self._paths.recovery.with_name("limits.recovery.json")
        try:
            self._io.replace_text(
                marker,
                json.dumps({"schema_version": 1, "kind": "fleet_limits_quarantine", "reason": reason}) + "\n",
            )
        except Exception:
            pass

    def _load_limits(self) -> dict[str, dict[str, str | None]]:
        self._ensure_layout()
        try:
            text = self._io.read_text(
                self._paths.limits,
                MAX_LIMIT_BYTES,
                "could_not_read_fleet_limits",
            )
            if text is None:
                return {}
            raw = json.loads(text)
            if (
                not isinstance(raw, dict)
                or set(raw) != {"schema_version", "accounts"}
                or raw.get("schema_version") != 1
                or not isinstance(raw.get("accounts"), dict)
            ):
                raise ValueError("invalid_fleet_limits")
            entries: dict[str, dict[str, str | None]] = {}
            for account_id, value in raw["accounts"].items():
                if (
                    not isinstance(account_id, str)
                    or not _ACCOUNT_ID_RE.fullmatch(account_id)
                    or not isinstance(value, dict)
                    or set(value) != {"reset_at_utc", "reason"}
                ):
                    raise ValueError("invalid_fleet_limits")
                reason = value.get("reason")
                if not isinstance(reason, str) or not _LIMIT_REASON_RE.fullmatch(reason):
                    raise ValueError("invalid_fleet_limits")
                entries[account_id] = {
                    "reset_at_utc": self._parse_time(value.get("reset_at_utc")),
                    "reason": reason,
                }
            return entries
        except Exception:
            self._quarantine_limits()
            if self._read_only:
                raise ValueError("invalid_fleet_limits") from None
            return {}

    def _write_limits(self, entries: dict[str, dict[str, str | None]]) -> None:
        document = {"schema_version": 1, "accounts": entries}
        text = json.dumps(document, indent=2, sort_keys=True) + "\n"
        self._io.replace_text(self._paths.limits, text)
        if self._load_limits() != entries:
            raise ValueError("fleet_limits_write_verification_failed")

    def _quarantine_rate_limits(self, reason: str = "invalid_gemini_rate_limits") -> None:
        marker = self._paths.recovery.with_name("rate-limits.recovery.json")
        try:
            self._io.replace_text(
                marker,
                json.dumps({"schema_version": 1, "kind": "gemini_rate_limits_quarantine", "reason": reason}) + "\n",
            )
        except Exception:
            pass

    def _parse_rate_state(self, state: object) -> dict[str, object]:
        required = {
            "next_allowed_at_utc",
            "cooldown_until_utc",
            "in_flight",
            "consecutive_429",
        }
        if not isinstance(state, dict) or set(state) != required:
            raise ValueError("invalid_gemini_rate_limits")
        next_allowed = self._parse_time(state.get("next_allowed_at_utc"))
        cooldown = self._parse_time(state.get("cooldown_until_utc"))
        if next_allowed is None:
            raise ValueError("invalid_gemini_rate_limits")
        in_flight = state.get("in_flight")
        if in_flight is not None:
            if (
                not isinstance(in_flight, dict)
                or set(in_flight) != {"reservation_id", "expires_at_utc"}
                or not isinstance(in_flight.get("reservation_id"), str)
                or not re.fullmatch(r"[0-9a-f]{32}", in_flight["reservation_id"])
                or self._parse_time(in_flight.get("expires_at_utc")) is None
            ):
                raise ValueError("invalid_gemini_rate_limits")
            in_flight = {
                "reservation_id": in_flight["reservation_id"],
                "expires_at_utc": in_flight["expires_at_utc"],
            }
        consecutive = state.get("consecutive_429")
        if isinstance(consecutive, bool) or not isinstance(consecutive, int) or not 0 <= consecutive <= 32:
            raise ValueError("invalid_gemini_rate_limits")
        return {
            "next_allowed_at_utc": next_allowed,
            "cooldown_until_utc": cooldown,
            "in_flight": in_flight,
            "consecutive_429": consecutive,
        }

    def _load_rate_limits(self) -> dict[str, dict[str, object]]:
        self._ensure_layout()
        try:
            text = self._io.read_text(
                self._paths.rate_limits,
                MAX_RATE_LIMIT_BYTES,
                "could_not_read_gemini_rate_limits",
            )
            if text is None:
                return {}
            raw = json.loads(text)
            if not isinstance(raw, dict) or set(raw) != {"schema_version", "accounts"} or not isinstance(raw.get("accounts"), dict):
                raise ValueError("invalid_gemini_rate_limits")
            version = raw.get("schema_version")
            if not isinstance(version, int):
                raise ValueError("invalid_gemini_rate_limits")

            entries: dict[str, dict[str, object]] = {}
            if version == 1:
                required = {"next_allowed_at_utc", "cooldown_until_utc", "in_flight", "consecutive_429"}
                for account_id, value in raw["accounts"].items():
                    if (
                        not isinstance(account_id, str)
                        or not _ACCOUNT_ID_RE.fullmatch(account_id)
                        or not isinstance(value, dict)
                        or set(value) != required
                    ):
                        raise ValueError("invalid_gemini_rate_limits")
                    state = self._parse_rate_state(value)
                    entries[account_id] = {**state, "models": {}}
            elif version == 2:
                account_keys = {
                    "next_allowed_at_utc",
                    "cooldown_until_utc",
                    "in_flight",
                    "consecutive_429",
                    "models",
                }
                for account_id, value in raw["accounts"].items():
                    if (
                        not isinstance(account_id, str)
                        or not _ACCOUNT_ID_RE.fullmatch(account_id)
                        or not isinstance(value, dict)
                        or set(value) != account_keys
                    ):
                        raise ValueError("invalid_gemini_rate_limits")
                    state = self._parse_rate_state(
                        {
                            "next_allowed_at_utc": value.get("next_allowed_at_utc"),
                            "cooldown_until_utc": value.get("cooldown_until_utc"),
                            "in_flight": value.get("in_flight"),
                            "consecutive_429": value.get("consecutive_429"),
                        },
                    )
                    models = value.get("models")
                    if not isinstance(models, dict):
                        raise ValueError("invalid_gemini_rate_limits")
                    normalized_models: dict[str, dict[str, object]] = {}
                    for model_key, model_state in models.items():
                        if not isinstance(model_key, str) or self._normalize_gemini_model(model_key) != model_key:
                            raise ValueError("invalid_gemini_rate_limits")
                        normalized_models[model_key] = self._parse_rate_state(model_state)
                    state["models"] = normalized_models
                    entries[account_id] = state
            else:
                raise ValueError("invalid_gemini_rate_limits")
            return entries
        except Exception:
            self._quarantine_rate_limits()
            raise ValueError("invalid_gemini_rate_limits") from None

    def _write_rate_limits(self, entries: dict[str, dict[str, object]]) -> None:
        account_keys = {
            "next_allowed_at_utc",
            "cooldown_until_utc",
            "in_flight",
            "consecutive_429",
            "models",
        }
        normalized: dict[str, dict[str, object]] = {}
        for account_id, entry in entries.items():
            if (
                not isinstance(account_id, str)
                or not _ACCOUNT_ID_RE.fullmatch(account_id)
                or not isinstance(entry, dict)
                or set(entry) != account_keys
            ):
                raise ValueError("invalid_gemini_rate_limits")
            account_state = self._parse_rate_state({key: entry[key] for key in account_keys if key != "models"})
            models = entry["models"]
            if not isinstance(models, dict):
                raise ValueError("invalid_gemini_rate_limits")
            normalized_models: dict[str, dict[str, object]] = {}
            for model_key, model_entry in models.items():
                if not isinstance(model_key, str) or self._normalize_gemini_model(model_key) != model_key:
                    raise ValueError("invalid_gemini_rate_limits")
                normalized_models[model_key] = self._parse_rate_state(model_entry)
            normalized[account_id] = {**account_state, "models": normalized_models}
        document = {"schema_version": 2, "accounts": normalized}
        text = json.dumps(document, indent=2, sort_keys=True) + "\n"
        self._io.replace_text(self._paths.rate_limits, text)
        if self._load_rate_limits() != normalized:
            raise ValueError("gemini_rate_limits_write_verification_failed")

    def _load_usage(self) -> dict[str, list[dict[str, object]]]:
        self._ensure_layout()
        try:
            text = self._io.read_text(self._paths.usage, MAX_USAGE_BYTES, "could_not_read_gemini_usage")
            if text is None:
                return {}
            raw = json.loads(text)
            if not isinstance(raw, dict) or raw.get("schema_version") != 1 or not isinstance(raw.get("accounts"), dict):
                raise ValueError("invalid_gemini_usage")
            result: dict[str, list[dict[str, object]]] = {}
            for account_id, events in raw["accounts"].items():
                if not isinstance(account_id, str) or not _ACCOUNT_ID_RE.fullmatch(account_id) or not isinstance(events, list):
                    raise ValueError("invalid_gemini_usage")
                clean: list[dict[str, object]] = []
                for event in events:
                    if not isinstance(event, dict):
                        raise ValueError("invalid_gemini_usage")
                    timestamp = event.get("at_utc")
                    if self._parse_time(timestamp) is None:
                        raise ValueError("invalid_gemini_usage")
                    model = event.get("model")
                    if not isinstance(model, str) or not 1 <= len(model) <= 200:
                        raise ValueError("invalid_gemini_usage")
                    for key in ("input_tokens", "output_tokens", "tool_call_count"):
                        value = event.get(key, 0)
                        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 2**63 - 1:
                            raise ValueError("invalid_gemini_usage")
                    status = event.get("status")
                    if not isinstance(status, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", status):
                        raise ValueError("invalid_gemini_usage")
                    gate_action = event.get("gate_action")
                    if gate_action is not None and gate_action not in {
                        "allow", "defer_until", "rotate_account", "rotate_model", "reject",
                    }:
                        raise ValueError("invalid_gemini_usage")
                    gate_code = event.get("gate_code")
                    if gate_code is not None and gate_code not in GEMINI_GATE_DIAGNOSTICS:
                        raise ValueError("invalid_gemini_usage")
                    quota_scope = event.get("quota_scope")
                    quota_retry_after_seconds = event.get("quota_retry_after_seconds")
                    if not isinstance(quota_scope, str) and quota_scope is not None:
                        raise ValueError("invalid_gemini_usage")
                    if quota_scope is None:
                        quota_scope = None
                        quota_retry_after_seconds = None
                    elif quota_scope not in _USAGE_QUOTA_SCOPES:
                        raise ValueError("invalid_gemini_usage")
                    elif quota_retry_after_seconds is not None:
                        if (
                            isinstance(quota_retry_after_seconds, bool)
                            or not isinstance(quota_retry_after_seconds, int)
                            or quota_retry_after_seconds <= 0
                            or quota_retry_after_seconds > _GEMINI_MAX_USAGE_QUOTA_RETRY_SECONDS
                        ):
                            raise ValueError("invalid_gemini_usage")
                    else:
                        quota_retry_after_seconds = None
                    reset_at = event.get("next_reset_at_utc")
                    if reset_at is not None and self._parse_time(reset_at) is None:
                        raise ValueError("invalid_gemini_usage")
                    clean.append({
                        "at_utc": timestamp,
                        "model": model,
                        "input_tokens": event.get("input_tokens", 0),
                        "output_tokens": event.get("output_tokens", 0),
                        "tool_call_count": event.get("tool_call_count", 0),
                        "status": status,
                        "gate_action": gate_action,
                        "gate_code": gate_code,
                        "quota_scope": quota_scope,
                        "quota_retry_after_seconds": quota_retry_after_seconds,
                        "next_reset_at_utc": reset_at,
                    })
                result[account_id] = clean[-2000:]
            return result
        except Exception:
            marker = self._paths.recovery.with_name("usage.recovery.json")
            try:
                self._io.replace_text(
                    marker,
                    json.dumps({"schema_version": 1, "kind": "gemini_usage_quarantine"}) + "\n",
                )
            except Exception:
                pass
            raise ValueError("invalid_gemini_usage") from None

    def _write_usage(self, entries: dict[str, list[dict[str, object]]]) -> None:
        document = {"schema_version": 1, "accounts": entries}
        text = json.dumps(document, indent=2, sort_keys=True) + "\n"
        self._io.replace_text(self._paths.usage, text)
        if self._load_usage() != entries:
            raise ValueError("gemini_usage_write_verification_failed")

    @staticmethod
    def gemini_billing_group(account_id: str) -> str:
        match = re.fullmatch(r"the-hive-(\d+)", account_id)
        if match:
            number = int(match.group(1))
            return f"the-hive-account-{((number - 1) // 10) + 1}"
        return account_id

    @staticmethod
    def _normalize_gemini_model(model: str | None) -> str | None:
        if model is None:
            return None
        try:
            return validate_gemini_probe_model(model)
        except FleetRunnerError:
            return None

    @classmethod
    def gemini_quota_limits(cls, tier: str, model: str | None) -> dict[str, int] | None:
        """Return model-specific limits from the supplied AI Studio snapshots."""

        if not isinstance(tier, str):
            return None
        model_key = cls._normalize_gemini_model(model)
        limits = GEMINI_QUOTA_SNAPSHOTS.get(tier, {}).get(model_key or "")
        return dict(limits) if limits is not None else None

    @classmethod
    def gemini_quota_profile(
        cls,
        account_id: str,
        *,
        model: str | None = None,
    ) -> dict[str, object]:
        """Return billing metadata and model limits without guessing."""

        billing_group = cls.gemini_billing_group(account_id)
        tier = GEMINI_PROJECT_BILLING_TIERS.get(account_id, "unknown")
        tier1 = tier == "tier1"
        model_key = cls._normalize_gemini_model(model)
        project_limits = GEMINI_PROJECT_QUOTA_SNAPSHOTS.get(account_id, {})
        model_limits = project_limits.get(model_key or "")
        limits_by_model = {
            name: dict(values)
            for name, values in project_limits.items()
        }
        return {
            "billing_group": billing_group,
            "billing_tier": tier,
            "billing_tier_source": (
                GEMINI_QUOTA_SNAPSHOT_SOURCE if tier != "unknown" else "not_confirmed"
            ),
            "provider_quota_source": (
                GEMINI_QUOTA_SNAPSHOT_SOURCE if model_limits is not None else "ai_studio_dashboard"
            ),
            "quota_snapshot_source": GEMINI_QUOTA_SNAPSHOT_SOURCE if limits_by_model else None,
            "quota_model": model_key,
            "limits_by_model": limits_by_model,
            "rpm_limit": model_limits.get("rpm") if model_limits is not None else None,
            "tpm_limit": model_limits.get("tpm") if model_limits is not None else None,
            "rpd_limit": model_limits.get("rpd") if model_limits is not None else None,
            "spend_rate_limit_usd_per_10_minutes": (
                GEMINI_TIER1_SPEND_RATE_LIMIT_USD_PER_10_MINUTES if tier1 else None
            ),
            "billing_cap_usd_per_month": (
                GEMINI_TIER1_BILLING_CAP_USD_PER_MONTH if tier1 else None
            ),
            "local_request_interval_seconds": (
                GEMINI_TIER1_LOCAL_REQUEST_INTERVAL_SECONDS if tier1
                else GEMINI_MIN_REQUEST_INTERVAL_SECONDS
            ),
            "quota_scope": "project",
            "billing_scope": "billing_account",
        }

    def project_limit_identity(
        self,
        account_id: str,
        *,
        model: str | None = None,
    ) -> dict[str, object]:
        """Expose the quota scope explicitly.

        Gemini RPM/TPM/RPD counters are per project.  Billing tier and spend
        caps can additionally be shared by the billing group.  The local
        request limiter must therefore never use this group as its key.
        """

        snapshot = self.load()
        account = next((item for item in snapshot.accounts if item.account_id == account_id), None)
        billing_group = (
            account.billing_group
            if account is not None and account.billing_group
            else self.gemini_billing_group(account_id)
        )
        quota = self.gemini_quota_profile(account_id, model=model)
        return {
            "project_id": account_id,
            "rpm_tpm_rpd_scope": "project",
            "spend_and_tier_scope": "billing_account",
            **quota,
            "billing_group": billing_group,
        }

    def record_gemini_usage(
        self,
        account_id: str,
        *,
        model: str,
        input_tokens: int | None = None,
        output_tokens: int | None = None,
        tool_call_count: int | None = None,
        status: str = "completed",
        gate_action: str | None = None,
        gate_code: str | None = None,
        next_reset_at_utc: str | None = None,
        quota_observation: ProviderErrorQuotaObservation | None = None,
    ) -> dict[str, object]:
        if not isinstance(account_id, str) or not _ACCOUNT_ID_RE.fullmatch(account_id):
            raise ValueError("invalid_account")
        if not isinstance(model, str) or not 1 <= len(model) <= 200:
            raise ValueError("invalid_gemini_usage")
        if status not in {"completed", "failed", "cancelled", "timeout", "probe", "rate_limited"}:
            raise ValueError("invalid_gemini_usage")
        input_value = 0 if input_tokens is None else input_tokens
        output_value = 0 if output_tokens is None else output_tokens
        tool_call_value = 0 if tool_call_count is None else tool_call_count
        if (
            isinstance(input_value, bool) or not isinstance(input_value, int) or input_value < 0
            or isinstance(output_value, bool) or not isinstance(output_value, int) or output_value < 0
            or isinstance(tool_call_value, bool) or not isinstance(tool_call_value, int) or tool_call_value < 0
        ):
            raise ValueError("invalid_gemini_usage")
        if gate_action is not None and gate_action not in {
            "allow", "defer_until", "rotate_account", "rotate_model", "reject",
        }:
            raise ValueError("invalid_gemini_usage")
        if gate_code is not None and gate_code not in GEMINI_GATE_DIAGNOSTICS:
            raise ValueError("invalid_gemini_usage")
        if quota_observation is not None and (
            quota_observation.scope not in _USAGE_QUOTA_SCOPES
            or not isinstance(quota_observation.retry_after_seconds, int | type(None))
            or isinstance(quota_observation.retry_after_seconds, bool)
            or (quota_observation.retry_after_seconds is not None
                and (
                    quota_observation.retry_after_seconds <= 0
                    or quota_observation.retry_after_seconds > _GEMINI_MAX_USAGE_QUOTA_RETRY_SECONDS
                ))
        ):
            raise ValueError("invalid_gemini_usage")
        quota_scope = quota_observation.scope if quota_observation is not None else None
        quota_retry_after_seconds = quota_observation.retry_after_seconds if quota_observation is not None else None
        if next_reset_at_utc is not None and self._parse_time(next_reset_at_utc) is None:
            raise ValueError("invalid_gemini_usage")
        if (
            quota_retry_after_seconds is not None
            and isinstance(quota_retry_after_seconds, int)
            and quota_retry_after_seconds > _GEMINI_MAX_USAGE_QUOTA_RETRY_SECONDS
        ):
            raise ValueError("invalid_gemini_usage")
        with self._io.lock():
            now = self._rate_now()
            cutoff = now - timedelta(hours=24)
            entries = self._load_usage()
            events = []
            for event in entries.get(account_id, []):
                try:
                    at = datetime.fromisoformat(str(event["at_utc"]).replace("Z", "+00:00"))
                except (KeyError, TypeError, ValueError):
                    continue
                if at.tzinfo is not None and at.astimezone(timezone.utc) >= cutoff:
                    events.append(event)
            event = {
                "at_utc": self._rate_text(now),
                "model": model,
                "input_tokens": input_value,
                "output_tokens": output_value,
                "tool_call_count": tool_call_value,
                "status": status,
                "gate_action": gate_action,
                "gate_code": gate_code,
                "quota_scope": quota_scope,
                "quota_retry_after_seconds": quota_retry_after_seconds,
                "next_reset_at_utc": next_reset_at_utc,
            }
            events.append(event)
            entries[account_id] = events[-2000:]
            self._write_usage(entries)
        return self.gemini_usage_status(account_id)

    def gemini_usage_status(self, account_id: str, *, model: str | None = None) -> dict[str, object]:
        snapshot = self.load()
        now = self._rate_now()
        events = self._load_usage().get(account_id, [])
        recent_minute: list[dict[str, object]] = []
        recent_day: list[dict[str, object]] = []
        for event in events:
            try:
                at = datetime.fromisoformat(str(event["at_utc"]).replace("Z", "+00:00"))
            except (KeyError, TypeError, ValueError):
                continue
            if at.tzinfo is None:
                continue
            age = (now - at.astimezone(timezone.utc)).total_seconds()
            if 0 <= age < 60:
                recent_minute.append(event)
            if 0 <= age < 86400:
                recent_day.append(event)
        account = next((item for item in snapshot.accounts if item.account_id == account_id), None)
        probe_age = None
        probe_state = "unknown"
        if account is not None and account.last_probe_at_utc is not None:
            try:
                probed = datetime.fromisoformat(account.last_probe_at_utc.replace("Z", "+00:00"))
                probe_age = max(0, int((now - probed.astimezone(timezone.utc)).total_seconds()))
                probe_state = "fresh" if self._probe_is_fresh(account.last_probe_at_utc) else "stale"
            except (TypeError, ValueError, AttributeError):
                probe_state = "invalid"
        identity = self.project_limit_identity(account_id, model=model)
        observed = {
            "rpm": len(recent_minute),
            # Google defines TPM as input tokens per minute.  Output tokens
            # remain visible separately and are not folded into TPM.
            "tpm": sum(int(event.get("input_tokens", 0)) for event in recent_minute),
            "rpd": len(recent_day),
        }
        model_evaluations: dict[str, dict[str, object]] = {}
        model_names = {
            str(event.get("model"))
            for event in recent_day
            if isinstance(event.get("model"), str) and event.get("model")
        }
        if isinstance(model, str) and model:
            model_names.add(model)
        model_names = sorted(model_names)
        for model in model_names:
            model_minute = [event for event in recent_minute if event.get("model") == model]
            model_day = [event for event in recent_day if event.get("model") == model]
            model_observed = {
                "rpm": len(model_minute),
                "tpm": sum(int(event.get("input_tokens", 0)) for event in model_minute),
                "rpd": len(model_day),
                "tool_call_count": sum(int(event.get("tool_call_count", 0)) for event in model_day),
            }
            model_profile = self.gemini_quota_profile(account_id, model=model)
            model_limits = {
                "rpm": model_profile.get("rpm_limit"),
                "tpm": model_profile.get("tpm_limit"),
                "rpd": model_profile.get("rpd_limit"),
            }
            resets_at_utc = {
                "rpm": self._quota_window_reset(
                    model_minute, seconds=60, limit=model_limits["rpm"], metric="rpm",
                ),
                "tpm": self._quota_window_reset(
                    model_minute, seconds=60, limit=model_limits["tpm"], metric="tpm",
                ),
                "rpd": self._quota_window_reset(
                    model_day, seconds=86400, limit=model_limits["rpd"], metric="rpd",
                ),
            }
            utilization: dict[str, float | None] = {}
            for metric, value in model_observed.items():
                if metric == "tool_call_count":
                    continue
                limit = model_limits[metric]
                if isinstance(limit, (int, float)) and not isinstance(limit, bool) and limit > 0:
                    utilization[metric] = round(float(value) / float(limit) * 100, 2)
                else:
                    utilization[metric] = None
            model_quota_observation: dict[str, object] | None = None
            if model_day:
                for candidate_event in reversed(model_day):
                    scope = candidate_event.get("quota_scope")
                    if scope not in _USAGE_QUOTA_SCOPES:
                        continue
                    retry_after_seconds = candidate_event.get("quota_retry_after_seconds")
                    if (
                        retry_after_seconds is None
                        or (
                            isinstance(retry_after_seconds, int)
                            and not isinstance(retry_after_seconds, bool)
                        )
                    ):
                        model_quota_observation = {
                            "scope": scope,
                            "retry_after_seconds": retry_after_seconds,
                            "at_utc": candidate_event.get("at_utc"),
                        }
                    break
            model_evaluations[model] = {
                "model": model,
                "observed": model_observed,
                "limits": model_limits,
                "resets_at_utc": resets_at_utc,
                "utilization_percent": utilization,
                "state": (
                    "limits_unknown_dashboard_required"
                    if any(value is None for value in model_limits.values())
                    else "within_limits"
                ),
                "limits_source": model_profile["provider_quota_source"],
                "quota_observation": model_quota_observation,
            }
        if model is not None and model in model_evaluations:
            quota_evaluation = model_evaluations[model]
            quota_evaluation["scope"] = identity["quota_scope"]
        elif len(model_evaluations) == 1:
            quota_evaluation: dict[str, object] = next(iter(model_evaluations.values()))
            quota_evaluation["scope"] = identity["quota_scope"]
        elif model_evaluations:
            quota_evaluation = {
                "state": "mixed_models",
                "scope": identity["quota_scope"],
                "limits_source": identity["provider_quota_source"],
                "models": model_evaluations,
            }
        else:
            quota_evaluation = {
                "state": "model_required",
                "scope": identity["quota_scope"],
                "limits_source": identity["provider_quota_source"],
                "limits_by_model": identity["limits_by_model"],
            }
        return {
            "account_id": account_id,
            **identity,
            "probe_state": probe_state,
            "probe_age_seconds": probe_age,
            "rpm_observed": len(recent_minute),
            "tpm_observed": observed["tpm"],
            "output_tokens_per_minute_observed": sum(int(event.get("output_tokens", 0)) for event in recent_minute),
            "tool_call_count_24h": sum(int(event.get("tool_call_count", 0)) for event in recent_day),
            "rpd_observed": len(recent_day),
            "input_tokens_24h": sum(int(event.get("input_tokens", 0)) for event in recent_day),
            "output_tokens_24h": sum(int(event.get("output_tokens", 0)) for event in recent_day),
            "last_request_at_utc": events[-1].get("at_utc") if events else None,
            "event_count_24h": len(recent_day),
            "last_gate": (
                {
                    "action": events[-1].get("gate_action"),
                    "code": events[-1].get("gate_code"),
                }
                if events and events[-1].get("gate_action") is not None and events[-1].get("gate_code") is not None
                else None
            ),
            "next_known_reset_at_utc": events[-1].get("next_reset_at_utc") if events else None,
            "quota_evaluation": quota_evaluation,
            "spend_evaluation": {
                "state": "billing_export_required",
                "scope": identity["billing_scope"],
                "limit_usd_per_10_minutes": identity["spend_rate_limit_usd_per_10_minutes"],
                "billing_cap_usd_per_month": identity["billing_cap_usd_per_month"],
                "observed_spend_usd": None,
            },
            "raw_output": "not_returned",
        }

    def gemini_usage_watchdog(self) -> dict[str, object]:
        snapshot = self.load()
        accounts = [
            self.gemini_usage_status(account.account_id)
            for account in snapshot.accounts
            if account.provider.value == "gemini_api"
        ]
        stale = [item["account_id"] for item in accounts if item["probe_state"] in {"stale", "unknown", "invalid"}]
        return {
            "provider": "gemini_api",
            "account_count": len(accounts),
            "accounts": accounts,
            "stale_or_unknown_accounts": stale,
            "state": "ready" if not stale else "probe_deferred_until_invocation",
            "probe_policy": "probe_once_when_invocation_admission_sees_stale_or_unknown",
            "limits_source": "observed_project_counters; RPM/TPM/RPD caps must be supplied by the AI Studio dashboard",
            "recent_events": self.gemini_event_status(),
            "raw_output": "not_returned",
        }

    def gemini_event_status(self, limit: int = 20) -> list[dict[str, object]]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("invalid_gemini_event_limit")
        try:
            text = self._io.read_text(self._paths.events, MAX_EVENT_BYTES, "could_not_read_gemini_events") or ""
        except Exception:
            return []
        result: list[dict[str, object]] = []
        for line in text.splitlines()[-limit:]:
            try:
                value = json.loads(line)
            except (TypeError, UnicodeDecodeError, json.JSONDecodeError):
                continue
            if isinstance(value, dict):
                value.pop("raw_output", None)
                result.append(value)
        return result

    def record_gemini_event(
        self,
        *,
        event_type: str,
        agent_id: str | None,
        account_id: str | None,
        assignment_id: str | None,
        status: str,
        reason: str | None = None,
        model: str | None = None,
        input_tokens: int | None = None,
        output_tokens: int | None = None,
        tool_call_count: int | None = None,
        gate_action: str | None = None,
        gate_code: str | None = None,
        next_reset_at_utc: str | None = None,
        diagnostic_code: ProbeDiagnosticCode | None = None,
        process_phase: ProbeProcessPhase | None = None,
        process_output_shape: ProbeOutputShape | None = None,
        process_stdout_shape: ProbeStdoutShape | None = None,
        process_stdout_event_class: ProbeStdoutEventClass | None = None,
        process_stdout_error_seen: bool | None = None,
    ) -> dict[str, object]:
        """Append a bounded, redacted Gemini event for master/dispatcher status."""

        if self._read_only:
            return {"recorded": False, "reason": "read_only"}
        normalized_diagnostic_code = normalize_gemini_probe_diagnostic_code(diagnostic_code)
        normalized_process_phase = normalize_gemini_probe_process_phase(process_phase)
        normalized_process_output_shape = FleetService._normalize_probe_output_shape_for_timeout(
            normalized_diagnostic_code,
            normalized_process_phase,
            process_output_shape,
        )
        normalized_process_stdout_shape = FleetService._normalize_probe_stdout_shape_for_timeout(
            normalized_diagnostic_code,
            normalized_process_phase,
            process_stdout_shape,
        )
        normalized_process_stdout_event_class = normalize_gemini_probe_stdout_event_class(
            process_stdout_event_class,
        )
        normalized_process_stdout_error_seen = (
            process_stdout_error_seen if isinstance(process_stdout_error_seen, bool) else None
        )
        values = {
            "event_type": event_type,
            "agent_id": agent_id,
            "account_id": account_id,
            "assignment_id": assignment_id,
            "status": status,
            "reason": _redacted_gemini_event_reason(reason),
            "model": model,
            "input_tokens": input_tokens or 0,
            "output_tokens": output_tokens or 0,
            "tool_call_count": tool_call_count or 0,
            "gate_action": gate_action,
            "gate_code": gate_code,
            "next_reset_at_utc": next_reset_at_utc,
        }
        if normalized_diagnostic_code is not None:
            values["diagnostic_code"] = normalized_diagnostic_code
        if normalized_process_phase is not None:
            values["process_phase"] = normalized_process_phase
        if normalized_process_output_shape is not None:
            values["process_output_shape"] = normalized_process_output_shape
        if normalized_process_stdout_shape is not None:
            values["process_stdout_shape"] = normalized_process_stdout_shape
            if (
                normalized_process_stdout_shape == "gemini_probe_stdout_jsonl_incomplete"
                and normalized_process_stdout_event_class is not None
                and normalized_process_stdout_error_seen is not None
            ):
                values["process_stdout_event_class"] = normalized_process_stdout_event_class
                values["process_stdout_error_seen"] = normalized_process_stdout_error_seen
        for key in ("event_type", "status"):
            value = values[key]
            if not isinstance(value, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", value):
                raise ValueError("invalid_gemini_event")
        for key in ("agent_id", "account_id", "assignment_id", "reason", "model"):
            value = values[key]
            if value is not None and (not isinstance(value, str) or not 1 <= len(value) <= 300):
                raise ValueError("invalid_gemini_event")
        for key in ("input_tokens", "output_tokens", "tool_call_count"):
            value = values[key]
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 2**63 - 1:
                raise ValueError("invalid_gemini_event")
        if gate_action is not None and gate_action not in {
            "allow", "defer_until", "rotate_account", "rotate_model", "reject",
        }:
            raise ValueError("invalid_gemini_event")
        if gate_code is not None and gate_code not in GEMINI_GATE_DIAGNOSTICS:
            raise ValueError("invalid_gemini_event")
        if next_reset_at_utc is not None and self._parse_time(next_reset_at_utc) is None:
            raise ValueError("invalid_gemini_event")
        with self._io.lock():
            try:
                existing = self._io.read_text(self._paths.events, MAX_EVENT_BYTES, "could_not_read_gemini_events") or ""
            except Exception:
                existing = ""
            lines = [line for line in existing.splitlines() if line.strip()][-511:]
            entry = {
                "at_utc": self._rate_text(self._rate_now()),
                **values,
                "raw_output": "not_returned",
            }
            lines.append(json.dumps(entry, sort_keys=True, ensure_ascii=False))
            text = "\n".join(lines) + "\n"
            if len(text.encode("utf-8")) > MAX_EVENT_BYTES:
                lines = lines[-256:]
                text = "\n".join(lines) + "\n"
            self._io.replace_text(self._paths.events, text)
        return {"recorded": True, "event_type": event_type, "status": status}

    def _rate_now(self) -> datetime:
        now = self._io.utc_now()
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise ValueError("invalid_utc_clock")
        return now.astimezone(timezone.utc)

    @staticmethod
    def _rate_text(value: datetime) -> str:
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    @classmethod
    def _quota_window_reset(
        cls,
        events: list[dict[str, object]],
        *,
        seconds: int,
        limit: object,
        metric: str,
    ) -> str | None:
        if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
            return None
        observations: list[tuple[datetime, int]] = []
        for event in events:
            try:
                at = datetime.fromisoformat(str(event["at_utc"]).replace("Z", "+00:00"))
            except (KeyError, TypeError, ValueError):
                continue
            if at.tzinfo is not None:
                weight = int(event.get("input_tokens", 0)) if metric == "tpm" else 1
                observations.append((at.astimezone(timezone.utc), weight))
        observed = sum(weight for _at, weight in observations)
        if observed < limit:
            return None
        for at, weight in sorted(observations):
            observed -= weight
            if observed < limit:
                return cls._rate_text(at + timedelta(seconds=seconds))
        return None

    @staticmethod
    def _retry_after(now: datetime, *values: str | None) -> int:
        deadlines: list[datetime] = []
        for value in values:
            if value is None:
                continue
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                continue
            if parsed.tzinfo is not None and parsed > now:
                deadlines.append(parsed.astimezone(timezone.utc))
        if not deadlines:
            return 0
        return max(1, int(max((item - now).total_seconds() for item in deadlines) + 0.999))

    @staticmethod
    def _latest_deadline(now: datetime, *values: str | None) -> str | None:
        deadlines: list[datetime] = []
        for value in values:
            if value is None:
                continue
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                continue
            if parsed.tzinfo is not None and parsed.astimezone(timezone.utc) > now:
                deadlines.append(parsed.astimezone(timezone.utc))
        return FleetService._rate_text(max(deadlines)) if deadlines else None

    def reserve_gemini_request(self, account_id: str, *, model: str | None = None) -> GeminiRequestReservation:
        if self._read_only:
            raise FleetRateLimitError("rate_limiter_read_only", 60)
        if not isinstance(account_id, str) or not _ACCOUNT_ID_RE.fullmatch(account_id):
            raise FleetRateLimitError("rate_limiter_invalid_account", 60)
        model_key = self._normalize_gemini_model(model)
        with self._io.lock():
            now = self._rate_now()
            entries = self._load_rate_limits()
            quota = self.gemini_quota_profile(account_id, model=model_key)
            entry = entries.get(account_id)
            if entry is None:
                now_text = self._rate_text(now)
                entry = {
                    "next_allowed_at_utc": now_text,
                    "cooldown_until_utc": None,
                    "in_flight": None,
                    "consecutive_429": 0,
                    "models": {},
                }
                entries[account_id] = entry
            if entry is not None:
                retries: list[str | None] = [
                    entry.get("next_allowed_at_utc") if isinstance(entry.get("next_allowed_at_utc"), str) else None,
                    entry.get("cooldown_until_utc") if isinstance(entry.get("cooldown_until_utc"), str) else None,
                ]
                in_flight = entry.get("in_flight")
                if isinstance(in_flight, dict):
                    retries.append(in_flight.get("expires_at_utc") if isinstance(in_flight.get("expires_at_utc"), str) else None)
                if model_key is not None:
                    models = entry.get("models")
                    if isinstance(models, dict):
                        model_entry = models.get(model_key)
                        if isinstance(model_entry, dict):
                            retries.append(
                                model_entry.get("next_allowed_at_utc")
                                if isinstance(model_entry.get("next_allowed_at_utc"), str)
                                else None,
                            )
                            retries.append(
                                model_entry.get("cooldown_until_utc")
                                if isinstance(model_entry.get("cooldown_until_utc"), str)
                                else None,
                            )
                            model_in_flight = model_entry.get("in_flight")
                            if isinstance(model_in_flight, dict):
                                retries.append(
                                    model_in_flight.get("expires_at_utc")
                                    if isinstance(model_in_flight.get("expires_at_utc"), str)
                                    else None
                                )
                retry_after = self._retry_after(now, *retries)
                if retry_after:
                    raise FleetRateLimitError("gemini_local_rate_limit", retry_after)
            reservation_id = uuid.uuid4().hex
            expires = now + timedelta(seconds=GEMINI_REQUEST_LEASE_SECONDS)
            previous_cooldown = entry.get("cooldown_until_utc")
            next_allowed = self._rate_text(now + timedelta(seconds=int(quota["local_request_interval_seconds"])))
            reservation_text = self._rate_text(expires)
            entry["next_allowed_at_utc"] = next_allowed
            entry["cooldown_until_utc"] = previous_cooldown if isinstance(previous_cooldown, str) else None
            entry["in_flight"] = {"reservation_id": reservation_id, "expires_at_utc": reservation_text}
            if model_key is not None:
                models = entry["models"]
                if not isinstance(models, dict):
                    raise ValueError("invalid_gemini_rate_limits")
                model_entry = models.get(model_key)
                if not isinstance(model_entry, dict):
                    model_entry = {
                        "next_allowed_at_utc": next_allowed,
                        "cooldown_until_utc": None,
                        "in_flight": None,
                        "consecutive_429": 0,
                    }
                model_entry["next_allowed_at_utc"] = next_allowed
                model_entry["in_flight"] = {"reservation_id": reservation_id, "expires_at_utc": reservation_text}
                models[model_key] = model_entry
            self._write_rate_limits(entries)
        return GeminiRequestReservation(account_id, model_key, reservation_id, self._rate_text(expires))

    def gemini_rate_status(self, account_id: str, *, model: str | None = None) -> dict[str, object]:
        """Return the local admission state without reserving a request."""

        now = self._rate_now()
        entry = self._load_rate_limits().get(account_id)
        model_key = self._normalize_gemini_model(model)
        if entry is None:
            return {
                "allowed": True,
                "reason": "ready",
                "retry_after_seconds": 0,
                **self.gemini_quota_profile(account_id, model=model_key),
            }
        rates: list[str | None] = [
            entry.get("next_allowed_at_utc") if isinstance(entry.get("next_allowed_at_utc"), str) else None,
            entry.get("cooldown_until_utc") if isinstance(entry.get("cooldown_until_utc"), str) else None,
        ]
        in_flight = entry.get("in_flight")
        if isinstance(in_flight, dict):
            rates.append(
                in_flight.get("expires_at_utc") if isinstance(in_flight.get("expires_at_utc"), str) else None
            )
        if model_key is not None:
            models = entry.get("models")
            if isinstance(models, dict):
                model_entry = models.get(model_key)
                if isinstance(model_entry, dict):
                    rates.extend([
                        model_entry.get("next_allowed_at_utc")
                        if isinstance(model_entry.get("next_allowed_at_utc"), str)
                        else None,
                        model_entry.get("cooldown_until_utc")
                        if isinstance(model_entry.get("cooldown_until_utc"), str)
                        else None,
                    ])
                    model_in_flight = model_entry.get("in_flight")
                    if isinstance(model_in_flight, dict):
                        rates.append(
                            model_in_flight.get("expires_at_utc")
                            if isinstance(model_in_flight.get("expires_at_utc"), str)
                            else None
                        )
        retry_after = self._retry_after(now, *rates)
        defer_until = self._latest_deadline(now, *rates)
        return {
            "allowed": retry_after == 0,
            "reason": "ready" if retry_after == 0 else "gemini_local_rate_limit",
            "retry_after_seconds": retry_after,
            "defer_until": defer_until,
            **self.gemini_quota_profile(account_id, model=model_key),
        }

    @staticmethod
    def _gate_decision(
        action: str,
        code: str,
        *,
        account_id: str | None,
        model: str | None,
        defer_until: str | None = None,
        target_agent_id: str | None = None,
        openai_fallback_reason: str | None = None,
    ) -> GeminiGateDecision:
        code = map_gemini_gate_code(code)
        diagnostic = GEMINI_GATE_DIAGNOSTICS[code]
        return GeminiGateDecision(
            action,
            code,
            str(diagnostic["reason"]),
            str(diagnostic["severity"]),
            bool(diagnostic["retryable"]),
            account_id,
            model,
            defer_until,
            target_agent_id,
            openai_fallback_reason,
        )

    def _gemini_agent_gate_code(
        self,
        agent: object,
        *,
        snapshot: FleetSnapshot | FleetSnapshotV2,
        inventory: InventorySnapshot,
    ) -> tuple[str, str | None]:
        agent_id = getattr(agent, "agent_id", None)
        account_id = getattr(agent, "account_id", None)
        model = getattr(agent, "model", None)
        if not isinstance(agent_id, str) or not isinstance(account_id, str) or not isinstance(model, str):
            return "gemini_gate_unknown", None
        account_gate = self.account_gate(agent_id, snapshot=snapshot, inventory=inventory)
        if not account_gate.allowed:
            account = next((item for item in snapshot.accounts if item.account_id == account_id), None)
            reset_at = account.reset_at_utc if account is not None else None
            return map_gemini_gate_code(account_gate.reason), reset_at
        usage = self.gemini_usage_status(account_id, model=model)
        evaluation = usage.get("quota_evaluation")
        if not isinstance(evaluation, Mapping):
            return "gemini_limits_unknown", None
        observed = evaluation.get("observed")
        limits = evaluation.get("limits")
        resets = evaluation.get("resets_at_utc")
        quota_observation = evaluation.get("quota_observation")
        if isinstance(quota_observation, Mapping):
            scope = quota_observation.get("scope")
            retry_after_seconds = quota_observation.get("retry_after_seconds")
            observed_at = quota_observation.get("at_utc")
            if scope in {"model", "account", "unknown"}:
                deferred_until = None
                valid_retry_observation = False
                if (
                    isinstance(retry_after_seconds, int)
                    and not isinstance(retry_after_seconds, bool)
                    and 0 < retry_after_seconds <= _GEMINI_MAX_USAGE_QUOTA_RETRY_SECONDS
                ):
                    observed_at_utc = self._parse_time(observed_at)
                    if observed_at_utc is not None:
                        try:
                            defer_at = datetime.fromisoformat(observed_at_utc.replace("Z", "+00:00"))
                        except ValueError:
                            defer_at = None
                        else:
                            if defer_at.tzinfo is not None:
                                deferred_at = defer_at.astimezone(timezone.utc) + timedelta(seconds=retry_after_seconds)
                                now = self._rate_now()
                                if now < deferred_at:
                                    deferred_until = self._rate_text(deferred_at)
                                valid_retry_observation = True
                if scope == "model":
                    if deferred_until is not None:
                        return "gemini_model_limited", deferred_until
                    if not valid_retry_observation:
                        return "gemini_account_limited", None
                else:
                    return "gemini_account_limited", deferred_until
        rate = self.gemini_rate_status(account_id, model=model)
        if rate["allowed"] is not True:
            return "gemini_local_rate_limited", rate.get("defer_until") if isinstance(rate.get("defer_until"), str) else None
        if not isinstance(observed, Mapping) or not isinstance(limits, Mapping):
            return "gemini_limits_unknown", None
        for metric, code in (("rpm", "gemini_rpm_exhausted"), ("tpm", "gemini_tpm_exhausted"), ("rpd", "gemini_rpd_exhausted")):
            value = observed.get(metric)
            limit = limits.get(metric)
            if isinstance(limit, int) and not isinstance(limit, bool) and limit > 0:
                if isinstance(value, int) and not isinstance(value, bool) and value >= limit:
                    reset_at = resets.get(metric) if isinstance(resets, Mapping) else None
                    return code, reset_at if isinstance(reset_at, str) else None
            else:
                return "gemini_limits_unknown", None
        return "gemini_ready", None

    def gemini_headless_gate(self, agent_id: str) -> GeminiGateDecision:
        """Decide one Gemini headless start before secret or process access."""

        snapshot = self.load()
        inventory = build_inventory(snapshot, self._pool_root)
        agent = inventory.agents.get(agent_id)
        if agent is None or agent.provider is not Provider.GEMINI_API:
            return self._gate_decision("reject", "gemini_account_unavailable", account_id=None, model=None)
        code, defer_until = self._gemini_agent_gate_code(agent, snapshot=snapshot, inventory=inventory)
        if code in {"gemini_ready", "gemini_limits_unknown"}:
            return self._gate_decision("allow", code, account_id=agent.account_id, model=agent.model)

        ready_candidates: dict[str, object] = {}
        selection_candidates: list[SelectionCandidate] = []
        for candidate in inventory.agents.values():
            if candidate.agent_id == agent.agent_id or candidate.provider is not Provider.GEMINI_API or not candidate.enabled:
                continue
            candidate_code, _candidate_reset = self._gemini_agent_gate_code(
                candidate, snapshot=snapshot, inventory=inventory,
            )
            if candidate_code not in {"gemini_ready", "gemini_limits_unknown"}:
                continue
            ready_candidates[candidate.agent_id] = candidate
            selection_candidates.append(SelectionCandidate(
                agent_id=candidate.agent_id,
                account_key=candidate.account_id or candidate.agent_id,
                model_id=candidate.model,
                task_kind=TaskKind.COMPLEX,
                model_role=ModelRole.PRIMARY,
                rotation_distance=0 if candidate.account_id == agent.account_id else 1,
            ))
        rotation = preview_selection(
            selection_candidates,
            policy=SelectionPolicy(sp3=True),
            now=self._rate_now(),
            ledger=FairnessLedger({}),
        )
        if rotation.selected is not None:
            candidate = ready_candidates[rotation.selected.agent_id]
            action = "rotate_model" if candidate.account_id == agent.account_id else "rotate_account"
            return self._gate_decision(
                action,
                code,
                account_id=agent.account_id,
                model=agent.model,
                target_agent_id=candidate.agent_id,
            )

        fallback_available = any(
            candidate.provider in {Provider.OPENAI_API, Provider.OPENAI_CHATGPT}
            and self.account_gate(candidate.agent_id, snapshot=snapshot, inventory=inventory).allowed
            for candidate in inventory.agents.values()
        )
        action = "defer_until" if defer_until is not None else "reject"
        return self._gate_decision(
            action,
            code,
            account_id=agent.account_id,
            model=agent.model,
            defer_until=defer_until,
            openai_fallback_reason=(
                "Gemini rotation exhausted; eligible OpenAI fallback may be selected."
                if fallback_available else None
            ),
        )

    def release_gemini_request(
        self,
        reservation: GeminiRequestReservation,
        *,
        outcome: str,
        reset_at_utc: str | None = None,
    ) -> None:
        if self._read_only:
            return
        if outcome not in {"completed", "provider_error", "rate_limited"}:
            raise ValueError("invalid_gemini_rate_outcome")
        with self._io.lock():
            now = self._rate_now()
            entries = self._load_rate_limits()
            entry = entries.get(reservation.account_id)
            if not isinstance(entry, dict):
                return
            account_in_flight = entry.get("in_flight")
            if (
                not isinstance(account_in_flight, dict)
                or account_in_flight.get("reservation_id") != reservation.reservation_id
            ):
                return
            model_entry: dict[str, object] | None = None
            if reservation.model is not None:
                models = entry.get("models")
                if not isinstance(models, dict):
                    return
                candidate = models.get(reservation.model)
                if not isinstance(candidate, dict):
                    return
                model_entry = candidate
                model_in_flight = model_entry.get("in_flight")
                if (
                    not isinstance(model_in_flight, dict)
                    or model_in_flight.get("reservation_id") != reservation.reservation_id
                ):
                    return

            def release_state(state: dict[str, object], *, limited: bool) -> None:
                cooldown = state.get("cooldown_until_utc")
                consecutive = state.get("consecutive_429", 0)
                if not isinstance(consecutive, int) or isinstance(consecutive, bool):
                    consecutive = 0
                if limited:
                    consecutive = min(32, consecutive + 1)
                    cooldown_at: datetime | None = None
                    if reset_at_utc is not None:
                        try:
                            cooldown_at = datetime.fromisoformat(reset_at_utc.replace("Z", "+00:00"))
                        except ValueError:
                            cooldown_at = None
                        if cooldown_at is not None and cooldown_at.tzinfo is not None:
                            cooldown_at = cooldown_at.astimezone(timezone.utc)
                    if cooldown_at is None or cooldown_at <= now:
                        seconds = min(
                            GEMINI_MAX_429_COOLDOWN_SECONDS,
                            GEMINI_INITIAL_429_COOLDOWN_SECONDS * (2 ** min(consecutive - 1, 6)),
                        )
                        cooldown_at = now + timedelta(seconds=seconds)
                    cooldown = self._rate_text(cooldown_at)
                    state["next_allowed_at_utc"] = cooldown
                elif isinstance(cooldown, str) and self._retry_after(now, cooldown) == 0:
                    cooldown = None
                    consecutive = 0
                state["cooldown_until_utc"] = cooldown if isinstance(cooldown, str) else None
                state["consecutive_429"] = consecutive
                state["in_flight"] = None

            release_state(entry, limited=outcome == "rate_limited" and reservation.model is None)
            if reservation.model is not None and outcome == "rate_limited":
                entry["next_allowed_at_utc"] = self._rate_text(now)
            if model_entry is not None:
                release_state(model_entry, limited=outcome == "rate_limited")
            entries[reservation.account_id] = entry
            self._write_rate_limits(entries)

    def _overlay_limits(
        self,
        snapshot: FleetSnapshot | FleetSnapshotV2,
        entries: dict[str, dict[str, str | None]],
    ) -> FleetSnapshot | FleetSnapshotV2:
        now = self._io.utc_now()
        active_entries: dict[str, dict[str, str | None]] = {}
        expired_ids: set[str] = set()
        for account_id, entry in entries.items():
            reset_at = entry["reset_at_utc"]
            if reset_at is not None and isinstance(now, datetime) and now.tzinfo is not None:
                try:
                    parsed = datetime.fromisoformat(reset_at.replace("Z", "+00:00"))
                    if parsed.tzinfo is not None and parsed <= now:
                        expired_ids.add(account_id)
                        continue
                except ValueError:
                    continue
            active_entries[account_id] = entry
        accounts = tuple(
            dataclass_replace(
                account,
                limit_state=LimitState.LIMITED,
                reset_at_utc=active_entries[account.account_id]["reset_at_utc"],
                limit_reason=active_entries[account.account_id]["reason"],
            ) if account.account_id in active_entries else dataclass_replace(
                account,
                limit_state=LimitState.UNKNOWN,
                reset_at_utc=None,
                limit_reason=None,
            ) if account.account_id in expired_ids else account
            for account in snapshot.accounts
        )
        return normalize_fleet_document(
            fleet_document(dataclass_replace(snapshot, accounts=accounts))
        )

    @staticmethod
    def _check_generation(snapshot: FleetSnapshot | FleetSnapshotV2, expected_generation: int) -> None:
        if (
            isinstance(expected_generation, bool)
            or not isinstance(expected_generation, int)
            or snapshot.generation != expected_generation
        ):
            raise FleetConflictError("generation_conflict")

    def registry_snapshot(self) -> FleetSnapshot | FleetSnapshotV2:
        return self._load_registry()

    def load(self) -> FleetSnapshot | FleetSnapshotV2:
        return self._overlay_limits(self._load_registry(), self._load_limits())

    def public_snapshot(self) -> dict[str, object]:
        return public_fleet_snapshot(self.load())

    def commit_snapshot(
        self,
        snapshot: FleetSnapshot | FleetSnapshotV2,
        *,
        expected_generation: int,
    ) -> FleetSnapshot | FleetSnapshotV2:
        candidate = normalize_fleet_document(fleet_document(snapshot))
        with self._io.lock():
            current = self._load_registry()
            self._check_generation(current, expected_generation)
            if candidate.generation != current.generation + 1:
                raise FleetConflictError("generation_conflict")
            return self._write_registry(candidate)

    @staticmethod
    def _credential_binding_salt_metadata(path: Path) -> tuple[int, ...] | None:
        try:
            current = path.lstat()
        except FileNotFoundError:
            return None
        except OSError:
            raise FleetSecretError("credential_binding_unavailable") from None
        if (
            not stat.S_ISREG(current.st_mode)
            or getattr(current, "st_nlink", 1) != 1
            or stat.S_IMODE(current.st_mode) != 0o600
        ):
            raise FleetSecretError("credential_binding_unavailable")
        return (
            current.st_dev,
            current.st_ino,
            current.st_mode,
            current.st_nlink,
            current.st_size,
            current.st_mtime_ns,
            current.st_ctime_ns,
        )

    def _credential_binding_salt_locked(self, *, allow_create: bool = True) -> bytes:
        path = self._paths.secrets / ".credential-binding-salt"
        try:
            current = self._load_registry()
            has_existing_binding = isinstance(current, FleetSnapshotV2) and any(
                isinstance(account, FleetAccountV2)
                and account.provider is Provider.GEMINI_API
                and account.credential_binding_id is not None
                for account in current.accounts
            )
            before = self._credential_binding_salt_metadata(path)
            salt = self._io.read_bytes(
                path,
                _CREDENTIAL_BINDING_SALT_BYTES,
                "credential_binding_salt_read_failed",
            )
            after = self._credential_binding_salt_metadata(path)
            if salt is None:
                if before is not None or after is not None or has_existing_binding or not allow_create:
                    raise FleetSecretError("credential_binding_unavailable")
                salt = secrets.token_bytes(_CREDENTIAL_BINDING_SALT_BYTES)
                self._io.replace_bytes(path, salt, 0o600)
                created = self._credential_binding_salt_metadata(path)
                salt = self._io.read_bytes(
                    path,
                    _CREDENTIAL_BINDING_SALT_BYTES,
                    "credential_binding_salt_read_failed",
                )
                verified = self._credential_binding_salt_metadata(path)
                if created is None or verified != created:
                    raise FleetSecretError("credential_binding_unavailable")
            elif (
                before is None
                or after is None
                or before != after
            ):
                raise FleetSecretError("credential_binding_unavailable")
        except FleetSecretError:
            raise
        except Exception:
            raise FleetSecretError("credential_binding_unavailable") from None
        if salt is None or len(salt) != _CREDENTIAL_BINDING_SALT_BYTES:
            raise FleetSecretError("credential_binding_unavailable")
        return salt

    def _credential_binding_id_locked(
        self,
        secret_bytes: bytes,
        *,
        allow_create_salt: bool = True,
    ) -> str:
        if not isinstance(secret_bytes, bytes):
            raise FleetSecretError("credential_binding_unavailable")
        digest = hmac.new(
            self._credential_binding_salt_locked(allow_create=allow_create_salt),
            _CREDENTIAL_BINDING_DOMAIN + secret_bytes,
            hashlib.sha256,
        ).hexdigest()
        return f"hmac-sha256:{digest}"

    def _with_g_migration_binding_evidence(
        self,
        account_ids: tuple[str, ...],
        *,
        expected_generation: int,
        callback: Callable[[FleetSnapshot, Mapping[str, str]], _T],
    ) -> _T:
        if (
            type(account_ids) is not tuple
            or not account_ids
            or any(
                type(account_id) is not str
                or _ACCOUNT_ID_RE.fullmatch(account_id) is None
                for account_id in account_ids
            )
            or len(set(account_ids)) != len(account_ids)
            or not callable(callback)
        ):
            raise FleetSecretError("credential_binding_unknown")

        with self._io.lock():
            try:
                current = self._load_registry()
                if type(current) is not FleetSnapshot:
                    raise FleetSecretError("credential_binding_unknown")
                self._check_generation(current, expected_generation)
                accounts = {account.account_id: account for account in current.accounts}
                selected = []
                for account_id in account_ids:
                    account = accounts.get(account_id)
                    if (
                        type(account) is not FleetAccount
                        or account.provider is not Provider.GEMINI_API
                        or account.secret_state is not SecretState.CONFIGURED
                    ):
                        raise FleetSecretError("credential_binding_unknown")
                    selected.append(account)

                self._credential_binding_salt_locked(allow_create=False)
                bindings: dict[str, str] = {}
                for account in selected:
                    secret_path = self._paths.secrets / f"{account.account_id}.secret"
                    before = self._credential_binding_salt_metadata(secret_path)
                    secret_bytes = self._io.read_bytes(
                        secret_path,
                        MAX_SECRET_BYTES,
                        "credential_binding_unknown",
                    )
                    after = self._credential_binding_salt_metadata(secret_path)
                    if (
                        before is None
                        or after is None
                        or before != after
                        or type(secret_bytes) is not bytes
                        or not 1 <= len(secret_bytes) <= MAX_SECRET_BYTES
                    ):
                        raise FleetSecretError("credential_binding_unknown")
                    bindings[account.account_id] = self._credential_binding_id_locked(
                        secret_bytes,
                        allow_create_salt=False,
                    )
            except Exception:
                raise FleetSecretError("credential_binding_unknown") from None
            return callback(current, MappingProxyType(bindings))

    def set_secret(
        self,
        account_id: str,
        secret: str,
        *,
        expected_generation: int,
    ) -> dict[str, object]:
        if not isinstance(secret, str):
            raise FleetSecretError("invalid_secret")
        try:
            encoded = secret.encode("utf-8")
        except UnicodeError:
            raise FleetSecretError("invalid_secret") from None
        if not 1 <= len(encoded) <= MAX_SECRET_BYTES:
            raise FleetSecretError("invalid_secret")

        with self._io.lock():
            current = self._load_registry()
            self._check_generation(current, expected_generation)
            account = next((item for item in current.accounts if item.account_id == account_id), None)
            if account is None:
                raise FleetSecretError("invalid_account")
            secret_path = self._paths.secrets / f"{account.account_id}.secret"
            try:
                previous_secret = self._io.read_bytes(
                    secret_path,
                    MAX_SECRET_BYTES,
                    "secret_read_failed",
                )
            except Exception:
                raise FleetSecretError("secret_write_failed") from None
            try:
                self._io.replace_bytes(
                    secret_path,
                    encoded,
                    0o600,
                )
            except Exception:
                raise FleetSecretError("secret_write_failed") from None
            try:
                binding_id = (
                    self._credential_binding_id_locked(encoded)
                    if isinstance(current, FleetSnapshotV2)
                    and isinstance(account, FleetAccountV2)
                    and account.provider is Provider.GEMINI_API
                    else None
                )
                updated_account = dataclass_replace(
                    account,
                    secret_state=SecretState.CONFIGURED,
                    limit_state=LimitState.UNKNOWN,
                    reset_at_utc=None,
                    last_probe_at_utc=None,
                    limit_reason=None,
                    **({"credential_binding_id": binding_id} if binding_id is not None else {}),
                )
                updated = plan_account_upsert(
                    current,
                    updated_account,
                    expected_generation=current.generation,
                )
                stored = self._write_registry(updated)
            except Exception:
                with contextlib.suppress(Exception):
                    if previous_secret is None:
                        if self._io.remove_file is not None:
                            self._io.remove_file(secret_path)
                    else:
                        self._io.replace_bytes(secret_path, previous_secret, 0o600)
                raise
        return {"configured": True, "generation": stored.generation}

    def read_secret(
        self,
        account_id: str,
        *,
        expected_generation: int,
    ) -> str:
        """Read one configured secret for a bounded provider probe only."""

        with self._io.lock():
            current = self._load_registry()
            self._check_generation(current, expected_generation)
            account = next((item for item in current.accounts if item.account_id == account_id), None)
            if account is None:
                raise FleetSecretError("invalid_account")
            if account.secret_state is SecretState.MISSING:
                raise FleetSecretError("secret_missing")
            if account.secret_state is not SecretState.CONFIGURED:
                raise FleetSecretError("secret_unavailable")
            raw = self._io.read_bytes(
                self._paths.secrets / f"{account.account_id}.secret",
                MAX_SECRET_BYTES,
                "secret_read_failed",
            )
            if raw is None:
                raise FleetSecretError("secret_missing")
            try:
                secret = raw.decode("utf-8")
            except UnicodeDecodeError:
                raise FleetSecretError("secret_read_failed") from None
            if not 1 <= len(raw) <= MAX_SECRET_BYTES:
                raise FleetSecretError("secret_read_failed")
            return secret

    def delete_account(
        self,
        account_id: str,
        *,
        expected_generation: int,
    ) -> dict[str, object]:
        with self._io.lock():
            current = self._load_registry()
            self._check_generation(current, expected_generation)
            account = next((item for item in current.accounts if item.account_id == account_id), None)
            if account is None:
                raise FleetSecretError("invalid_account")
            if account.enabled:
                raise FleetSecretError("account_must_be_disabled")
            updated = plan_account_delete(current, account_id, expected_generation=current.generation)
            if account.secret_state is not SecretState.NOT_REQUIRED:
                if self._io.remove_file is None:
                    raise FleetSecretError("secret_cleanup_unavailable")
                try:
                    if not self._io.remove_file(self._paths.secrets / f"{account.account_id}.secret"):
                        raise FleetSecretError("secret_cleanup_failed")
                except FleetSecretError:
                    raise
                except Exception:
                    raise FleetSecretError("secret_cleanup_failed") from None
            stored = self._write_registry(updated)
            entries = self._load_limits()
            if account_id in entries:
                remaining = dict(entries)
                del remaining[account_id]
                self._write_limits(remaining)
        return {
            "deleted": True,
            "generation": stored.generation,
            "cleanup_pending": False,
        }

    def remove_secret_sidecar(
        self,
        account_id: str,
        *,
        expected_generation: int,
    ) -> bool:
        with self._io.lock():
            current = self._load_registry()
            self._check_generation(current, expected_generation)
            if not any(item.account_id == account_id for item in current.accounts):
                raise FleetSecretError("invalid_account")
            if self._io.remove_file is None:
                raise FleetSecretError("secret_cleanup_unavailable")
            try:
                return self._io.remove_file(self._paths.secrets / f"{account_id}.secret")
            except Exception:
                raise FleetSecretError("secret_cleanup_failed") from None

    def _mark_limited_locked(
        self,
        account_id: str,
        *,
        reset_at_utc: str | None,
        reason: str,
    ) -> FleetSnapshot:
        self._parse_time(reset_at_utc)
        if not isinstance(reason, str) or not _LIMIT_REASON_RE.fullmatch(reason):
            raise ValueError("invalid_fleet_limits")
        current = self._load_registry()
        if not any(item.account_id == account_id for item in current.accounts):
            raise ValueError("invalid_account")
        updated = mark_account_limit(
            current,
            account_id,
            reset_at_utc=reset_at_utc,
            reason=reason,
            expected_generation=current.generation,
        )
        entries = self._load_limits()
        updated_entries = dict(entries)
        updated_entries[account_id] = {
            "reset_at_utc": reset_at_utc,
            "reason": reason,
        }
        self._write_limits(updated_entries)
        return self._write_registry(updated)

    def mark_limited(
        self,
        account_id: str,
        *,
        reset_at_utc: str | None,
        reason: str,
    ) -> FleetSnapshot:
        with self._io.lock():
            return self._mark_limited_locked(
                account_id,
                reset_at_utc=reset_at_utc,
                reason=reason,
            )

    @staticmethod
    def _probe_status(
        snapshot: FleetSnapshot,
        *,
        ready: bool,
        reason: str,
        diagnostic_code: ProbeDiagnosticCode | None = None,
        process_phase: ProbeProcessPhase | None = None,
        process_output_shape: ProbeOutputShape | None = None,
        process_stdout_shape: ProbeStdoutShape | None = None,
        process_stdout_event_class: ProbeStdoutEventClass | None = None,
        process_stdout_error_seen: bool | None = None,
        model: str | None = None,
    ) -> dict[str, object]:
        status: dict[str, object] = {
            "probed": True,
            "generation": snapshot.generation,
            "ready": ready,
            "reason": reason,
        }
        normalized_process_phase = normalize_gemini_probe_process_phase(process_phase)
        if isinstance(process_phase, str) and normalized_process_phase:
            status["process_phase"] = process_phase
        normalized_diagnostic_code = normalize_gemini_probe_diagnostic_code(diagnostic_code)
        if isinstance(diagnostic_code, str) and normalized_diagnostic_code:
            status["diagnostic_code"] = diagnostic_code
        normalized_process_output_shape = FleetService._normalize_probe_output_shape_for_timeout(
            normalized_diagnostic_code,
            normalized_process_phase,
            process_output_shape,
        )
        normalized_process_stdout_shape = FleetService._normalize_probe_stdout_shape_for_timeout(
            normalized_diagnostic_code,
            normalized_process_phase,
            process_stdout_shape,
        )
        normalized_process_stdout_event_class = normalize_gemini_probe_stdout_event_class(
            process_stdout_event_class,
        )
        normalized_process_stdout_error_seen = (
            process_stdout_error_seen if isinstance(process_stdout_error_seen, bool) else None
        )
        if normalized_process_output_shape is not None:
            status["process_output_shape"] = normalized_process_output_shape
        if normalized_process_stdout_shape is not None:
            status["process_stdout_shape"] = normalized_process_stdout_shape
            if (
                normalized_process_stdout_shape == "gemini_probe_stdout_jsonl_incomplete"
                and normalized_process_stdout_event_class is not None
                and normalized_process_stdout_error_seen is not None
            ):
                status["process_stdout_event_class"] = normalized_process_stdout_event_class
                status["process_stdout_error_seen"] = normalized_process_stdout_error_seen
        if isinstance(model, str) and model:
            status["model"] = model
        return status

    @staticmethod
    def _normalize_probe_output_shape_for_timeout(
        diagnostic_code: ProbeDiagnosticCode | None,
        process_phase: ProbeProcessPhase | None,
        process_output_shape: ProbeOutputShape | None,
    ) -> ProbeOutputShape | None:
        normalized_diagnostic_code = normalize_gemini_probe_diagnostic_code(diagnostic_code)
        normalized_process_phase = normalize_gemini_probe_process_phase(process_phase)
        normalized_process_output_shape = normalize_gemini_probe_output_shape(process_output_shape)
        timeout_phases = frozenset({
            "gemini_probe_timeout_no_output",
            "gemini_probe_timeout_structured_no_terminal",
            "gemini_probe_timeout_output_unclassified",
        })
        if (
            normalized_diagnostic_code != "gemini_probe_process_timeout"
            or normalized_process_phase not in timeout_phases
            or normalized_process_output_shape is None
        ):
            return None
        return normalized_process_output_shape

    @staticmethod
    def _normalize_probe_stdout_shape_for_timeout(
        diagnostic_code: ProbeDiagnosticCode | None,
        process_phase: ProbeProcessPhase | None,
        process_stdout_shape: ProbeStdoutShape | None,
    ) -> ProbeStdoutShape | None:
        normalized_diagnostic_code = normalize_gemini_probe_diagnostic_code(diagnostic_code)
        normalized_process_phase = normalize_gemini_probe_process_phase(process_phase)
        normalized_process_stdout_shape = normalize_gemini_probe_stdout_shape(process_stdout_shape)
        timeout_phases = frozenset({
            "gemini_probe_timeout_no_output",
            "gemini_probe_timeout_structured_no_terminal",
            "gemini_probe_timeout_output_unclassified",
        })
        if (
            normalized_diagnostic_code != "gemini_probe_process_timeout"
            or normalized_process_phase not in timeout_phases
            or normalized_process_stdout_shape is None
        ):
            return None
        return normalized_process_stdout_shape


    @staticmethod
    def _updated_probe_account(
        account: FleetAccount,
        *,
        now: str,
        reason: str,
    ) -> FleetAccount:
        if reason == "ready":
            return dataclass_replace(
                account,
                limit_state=LimitState.READY,
                reset_at_utc=None,
                last_probe_at_utc=now,
                limit_reason=None,
            )
        if reason == "auth_invalid":
            return dataclass_replace(
                account,
                secret_state=SecretState.INVALID,
                limit_state=LimitState.UNKNOWN,
                reset_at_utc=None,
                last_probe_at_utc=None,
                limit_reason=None,
            )
        if reason == "secret_missing":
            return dataclass_replace(
                account,
                secret_state=SecretState.MISSING,
                limit_state=LimitState.UNKNOWN,
                reset_at_utc=None,
                last_probe_at_utc=None,
                limit_reason=None,
            )
        if reason in {"provider_unavailable", "model_unavailable"}:
            return dataclass_replace(
                account,
                secret_state=SecretState.CONFIGURED,
                limit_state=LimitState.UNKNOWN,
                reset_at_utc=None,
                last_probe_at_utc=None,
                limit_reason=reason,
            )
        return dataclass_replace(
            account,
            limit_state=LimitState.READY,
            reset_at_utc=None,
            last_probe_at_utc=now,
            limit_reason=reason,
        )

    def _utc_text(self) -> str:
        now = self._io.utc_now()
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise ValueError("invalid_utc_clock")
        return now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    def probe_account(
        self,
        account_id: str,
        probe: Callable[[FleetAccount], ProbeResult],
        *,
        model: str | None = None,
        expected_generation: int,
    ) -> dict[str, object]:
        with self._io.lock():
            current = self._load_registry()
            self._check_generation(current, expected_generation)
            account = next((item for item in current.accounts if item.account_id == account_id), None)
            if account is None:
                raise ValueError("invalid_account")
            probed_generation = current.generation

        reservation = None
        if account.provider.value == "gemini_api":
            reservation = self.reserve_gemini_request(
                account.account_id,
                model=model,
            )
        result: ProbeResult | None = None
        try:
            result = probe(account)
        except Exception:
            result = None
        finally:
            if reservation is not None:
                model_limited = False
                valid_model_limit = False
                if (
                    isinstance(result, ProbeResult)
                    and result.error is not None
                    and result.error.kind == "account_limited"
                    and result.error.quota_observation is not None
                    and isinstance(result.model, str)
                    and result.error.quota_observation.scope == "model"
                    and result.error.quota_observation.retry_after_seconds is not None
                    and isinstance(result.error.quota_observation.retry_after_seconds, int)
                    and not isinstance(result.error.quota_observation.retry_after_seconds, bool)
                    and 0 < result.error.quota_observation.retry_after_seconds <= _GEMINI_MAX_USAGE_QUOTA_RETRY_SECONDS
                ):
                    valid_model_limit = True
                if (
                    isinstance(result, ProbeResult)
                    and result.error is not None
                    and result.error.kind == "account_limited"
                    and result.error.quota_observation is not None
                    and isinstance(result.model, str)
                ):
                    model_limited = valid_model_limit
                    self.record_gemini_usage(
                        account.account_id,
                        model=result.model,
                        status="failed",
                        gate_action="defer_until",
                        gate_code="gemini_model_limited" if model_limited else "gemini_account_limited",
                        next_reset_at_utc=result.error.reset_at_utc,
                        quota_observation=result.error.quota_observation,
                    )
                rate_limited = (
                    isinstance(result, ProbeResult)
                    and result.error is not None
                    and result.error.kind == "account_limited"
                )
                self.release_gemini_request(
                    reservation,
                    outcome=(
                        "rate_limited" if rate_limited and not model_limited
                        else "completed" if isinstance(result, ProbeResult) and result.ok
                        else "provider_error"
                    ),
                    reset_at_utc=(
                        result.error.reset_at_utc
                        if rate_limited and not model_limited and result is not None and result.error is not None
                        else None
                    ),
                )

        with self._io.lock():
            latest = self._load_registry()
            self._check_generation(latest, probed_generation)
            latest_account = next(
                (item for item in latest.accounts if item.account_id == account_id),
                None,
            )
            if latest_account is None:
                raise FleetConflictError("generation_conflict")
            diagnostic_code: ProbeDiagnosticCode | None = None
            if (
                isinstance(result, ProbeResult)
                and result.provider is latest_account.provider
                and result.ok
                and result.error is None
            ):
                reason = "ready"
            elif (
                isinstance(result, ProbeResult)
                and result.provider is latest_account.provider
                and not result.ok
                and result.error is not None
            ):
                reason = {
                    "account_limited": "limit_active",
                    "auth_invalid": "auth_invalid",
                    "secret_missing": "secret_missing",
                    "provider_unavailable": "provider_unavailable",
                    "model_unavailable": "model_unavailable",
                    "runner_failed": "provider_unavailable",
                }.get(result.error.kind, "provider_unavailable")
                if (
                    result.error.kind == "account_limited"
                    and result.error.quota_observation is not None
                    and result.error.quota_observation.scope == "model"
                    and result.error.quota_observation.retry_after_seconds is not None
                    and isinstance(result.error.quota_observation.retry_after_seconds, int)
                    and not isinstance(result.error.quota_observation.retry_after_seconds, bool)
                    and 0 < result.error.quota_observation.retry_after_seconds <= _GEMINI_MAX_USAGE_QUOTA_RETRY_SECONDS
                ):
                    reason = "ready"

                diagnostic_code = (
                    result.error.diagnostic_code
                    if (
                        isinstance(result, ProbeResult)
                        and reason == "provider_unavailable"
                        and result.error is not None
                    ) else None
                )
            else:
                reason = "provider_unavailable"
            process_phase: ProbeProcessPhase | None = (
                result.process_phase
                if isinstance(result, ProbeResult)
                else None
            )
            process_output_shape: ProbeOutputShape | None = (
                result.process_output_shape
                if isinstance(result, ProbeResult)
                else None
            )
            process_stdout_shape: ProbeStdoutShape | None = (
                result.process_stdout_shape
                if isinstance(result, ProbeResult)
                else None
            )
            process_stdout_event_class = (
                result.process_stdout_event_class
                if isinstance(result, ProbeResult)
                else None
            )
            process_stdout_error_seen = (
                result.process_stdout_error_seen
                if isinstance(result, ProbeResult)
                else None
            )

            if reason == "limit_active":
                if isinstance(diagnostic_code, str):
                    diagnostic_code = None
                if (
                    isinstance(result, ProbeResult)
                    and result.error is not None
                ):
                    reset_at_utc = result.error.reset_at_utc
                else:
                    reset_at_utc = None
                if isinstance(reset_at_utc, str):
                    try:
                        parsed = datetime.fromisoformat(reset_at_utc.replace("Z", "+00:00"))
                    except ValueError:
                        parsed = None
                    else:
                        if parsed.tzinfo is None:
                            parsed = None
                else:
                    parsed = None
                if parsed is None or parsed <= self._rate_now():
                    try:
                        rate_status = self.gemini_rate_status(
                            account.account_id,
                            model=result.model if isinstance(result, ProbeResult) else None,
                        )
                    except Exception:
                        rate_status = {}
                    defer_until = rate_status.get("defer_until") if isinstance(rate_status, Mapping) else None
                    if isinstance(defer_until, str):
                        try:
                            parsed = datetime.fromisoformat(defer_until.replace("Z", "+00:00"))
                        except ValueError:
                            parsed = None
                        else:
                            if parsed.tzinfo is not None and parsed > self._rate_now():
                                reset_at_utc = self._rate_text(parsed.astimezone(timezone.utc))
                            else:
                                reset_at_utc = None
                    else:
                        reset_at_utc = None
                stored = self._mark_limited_locked(
                    account_id,
                    reset_at_utc=reset_at_utc,
                    reason="provider_429",
                )
                return self._probe_status(
                    stored,
                    ready=False,
                    reason=reason,
                    diagnostic_code=diagnostic_code,
                    process_phase=process_phase,
                    process_output_shape=process_output_shape,
                    process_stdout_shape=process_stdout_shape,
                    process_stdout_event_class=process_stdout_event_class,
                    process_stdout_error_seen=process_stdout_error_seen,
                    model=result.model if isinstance(result, ProbeResult) else None,
                )

            updated_account = self._updated_probe_account(
                latest_account,
                now=self._utc_text(),
                reason=reason,
            )
            updated = plan_account_upsert(
                latest,
                updated_account,
                expected_generation=latest.generation,
            )
            stored = self._write_registry(updated)
            if reason == "ready":
                entries = self._load_limits()
                if account_id in entries:
                    remaining = dict(entries)
                    del remaining[account_id]
                    self._write_limits(remaining)
            return self._probe_status(
                stored,
                ready=reason == "ready",
                reason=reason,
                diagnostic_code=diagnostic_code,
                process_phase=process_phase,
                process_output_shape=process_output_shape,
                process_stdout_shape=process_stdout_shape,
                process_stdout_event_class=process_stdout_event_class,
                process_stdout_error_seen=process_stdout_error_seen,
                model=result.model if isinstance(result, ProbeResult) else None,
            )

    def account_gate(
        self,
        agent_id: str,
        *,
        snapshot: FleetSnapshot | None = None,
        inventory: InventorySnapshot | None = None,
    ) -> AccountGateDecision:
        snapshot = snapshot or self.load()
        inventory = inventory or build_inventory(snapshot, self._pool_root)
        agent = inventory.agents.get(agent_id)
        if agent is None:
            return AccountGateDecision(False, "account_disabled", None, snapshot.generation)
        series = next(
            (item for item in snapshot.series if item.prefix == agent.series_prefix),
            None,
        )
        if series is None or not series.enabled:
            return AccountGateDecision(False, "account_disabled", None, snapshot.generation)
        return self._account_decision(
            snapshot,
            account_id=agent.account_id,
            provider=agent.provider,
        )

    def series_gate(
        self,
        series: FleetSeries,
        *,
        snapshot: FleetSnapshot | None = None,
    ) -> AccountGateDecision:
        snapshot = snapshot or self.load()
        if not series.enabled:
            return AccountGateDecision(
                False,
                "series_disabled",
                series.account_id,
                snapshot.generation,
            )
        return self._account_decision(
            snapshot,
            account_id=series.account_id,
            provider=series.provider,
        )

    def _account_decision(
        self,
        snapshot: FleetSnapshot | FleetSnapshotV2,
        *,
        account_id: str | None,
        provider: object,
    ) -> AccountGateDecision:
        if account_id is None:
            return AccountGateDecision(True, "ready", None, snapshot.generation)
        account = next(
            (item for item in snapshot.accounts if item.account_id == account_id),
            None,
        )
        if account is not None and account.provider is not provider:
            reason = "account_provider_mismatch"
        elif account is None or not account.enabled or account.limit_state is LimitState.DISABLED:
            reason = "account_disabled"
        elif (
            provider is Provider.GEMINI_API
            and isinstance(account, FleetAccountV2)
            and account.secret_state is SecretState.CONFIGURED
            and account.credential_binding_id is None
        ):
            reason = "credential_binding_unknown"
        elif account.secret_state is SecretState.MISSING:
            reason = "secret_missing"
        elif account.secret_state is SecretState.INVALID:
            reason = "auth_invalid"
        elif account.limit_reason == "provider_unavailable":
            reason = "provider_unavailable"
        elif account.limit_reason == "model_unavailable":
            reason = "model_unavailable"
        elif provider is Provider.OPENAI_CHATGPT:
            # Native Codex sessions are authenticated by each home’s
            # auth.json.  They have no provider quota probe and must not be
            # made stale merely because a Gemini-style probe timestamp is
            # absent.
            reason = "ready"
        elif account.limit_state is LimitState.LIMITED:
            reason = "limit_active"
        elif account.limit_state in {LimitState.UNKNOWN, LimitState.PROBING}:
            reason = "limit_unknown"
        elif account.limit_reason == "provider_unavailable":
            reason = "provider_unavailable"
        elif account.limit_reason == "model_unavailable":
            reason = "model_unavailable"
        elif not self._probe_is_fresh(account.last_probe_at_utc):
            reason = "probe_stale"
        else:
            reason = "ready"
        return AccountGateDecision(reason == "ready", reason, account_id, snapshot.generation)

    def _probe_is_fresh(self, value: str | None) -> bool:
        if value is None:
            return False
        try:
            probed_at = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return False
        now = self._io.utc_now()
        if not isinstance(now, datetime) or now.tzinfo is None or probed_at.tzinfo is None:
            return False
        age = (now.astimezone(timezone.utc) - probed_at.astimezone(timezone.utc)).total_seconds()
        return 0 <= age <= self._probe_max_age_seconds
