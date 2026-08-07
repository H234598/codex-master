"""Read-only, deterministic resource-selection primitives.

This module deliberately stops at preview/ordering.  It does not reserve a
resource, mutate a fairness ledger, or start/stop an agent.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from types import MappingProxyType


MICRO = 1_000_000
HALF_LIFE_SECONDS = 7 * 24 * 60 * 60
MAX_SERVICE_MICRO = 10**18
MAX_USAGE_WINDOWS = 64
MAX_USAGE_QUANTITY = 10**18
_USAGE_FIELDS = frozenset({
    "semantics", "unit", "value", "reset_kind", "confidence", "observed_at", "stale_after_seconds",
})


class SelectionError(ValueError):
    """Raised when a selection primitive receives an invalid value."""


class TaskKind(str, Enum):
    SIMPLE = "simple"
    COMPLEX = "complex"
    UNKNOWN = "unknown"


class ModelRole(str, Enum):
    PRIMARY = "primary"
    SECONDARY_SIMPLE = "secondary_simple"


class SelectionBand(str, Enum):
    SP0 = "sp0"
    SP1A = "sp1a"
    SP1B = "sp1b"
    SP2 = "sp2"
    SP3 = "sp3"


class AdmissionMode(str, Enum):
    """Runtime mode for the separate, read-only admission boundary."""

    OFF = "off"
    SHADOW = "shadow"
    ENFORCED = "enforced"


_BAND_RANK = {
    SelectionBand.SP0: 0,
    SelectionBand.SP1A: 1,
    SelectionBand.SP1B: 2,
    SelectionBand.SP2: 3,
    SelectionBand.SP3: 4,
}


def _aware(value: datetime, code: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise SelectionError(code)
    return value


@dataclass(frozen=True, slots=True)
class UsageObservation:
    """Typed usage-v2 observation used by the passive SP0 anchor."""

    semantics: str
    unit: str
    value: int
    reset_kind: str
    confidence: str
    observed_at: datetime
    stale_after_seconds: int = 900

    def __post_init__(self) -> None:
        if self.semantics not in {"remaining", "used"}:
            raise SelectionError("invalid_usage_semantics")
        if self.unit != "percent":
            raise SelectionError("invalid_usage_unit")
        if isinstance(self.value, bool) or not isinstance(self.value, int) or not 0 <= self.value <= 100:
            raise SelectionError("invalid_usage_value")
        if self.reset_kind not in {"rolling_unanchored", "rolling_anchored", "fixed"}:
            raise SelectionError("invalid_usage_reset_kind")
        if self.confidence not in {"verified", "observed", "unknown"}:
            raise SelectionError("invalid_usage_confidence")
        _aware(self.observed_at, "invalid_usage_timestamp")
        if (
            isinstance(self.stale_after_seconds, bool)
            or not isinstance(self.stale_after_seconds, int)
            or not 1 <= self.stale_after_seconds <= 86_400
        ):
            raise SelectionError("invalid_usage_freshness")

    def is_fresh(self, now: datetime) -> bool:
        now = _aware(now, "invalid_selection_time")
        age = (now - self.observed_at).total_seconds()
        return 0 <= age <= self.stale_after_seconds

    def is_passive_sp0_due(self, now: datetime) -> bool:
        return (
            self.semantics == "remaining"
            and self.unit == "percent"
            and self.value == 100
            and self.reset_kind == "rolling_unanchored"
            and self.confidence == "verified"
            and self.is_fresh(now)
        )


def normalize_usage_observation(payload: object) -> UsageObservation | None:
    """Normalize a typed usage-v2 payload without retaining private fields.

    Untyped/legacy payloads intentionally become ``None``.  A caller can
    expose that as an ``unknown`` source, but it cannot use it for SP0.
    """

    if not isinstance(payload, Mapping):
        raise SelectionError("invalid_usage_payload")
    if not any(field in payload for field in _USAGE_FIELDS):
        return None
    if set(payload) - _USAGE_FIELDS:
        raise SelectionError("invalid_usage_payload")
    required = {"semantics", "unit", "value", "reset_kind", "confidence", "observed_at"}
    if not required.issubset(payload):
        return None
    observed_at = payload["observed_at"]
    if not isinstance(observed_at, str) or not 1 <= len(observed_at) <= 40:
        raise SelectionError("invalid_usage_timestamp")
    try:
        parsed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SelectionError("invalid_usage_timestamp") from exc
    if parsed.tzinfo is None:
        raise SelectionError("invalid_usage_timestamp")
    return UsageObservation(
        payload["semantics"],
        payload["unit"],
        payload["value"],
        payload["reset_kind"],
        payload["confidence"],
        parsed,
        payload.get("stale_after_seconds", 900),
        )


@dataclass(frozen=True, slots=True)
class LimitWindow:
    """A secret-free, typed Usage-v2 budget window."""

    window_id: str
    budget_key: str
    applies_to_model_ids: tuple[str, ...]
    applies_to_model_roles: tuple[str, ...]
    quantity_semantics: str
    quantity_unit: str
    quantity_value: int
    capacity: int | None
    absolute_remaining: int | None
    window_kind: str
    constraint_relation: str
    reset_at_utc: datetime | None
    reset_kind: str | None
    observed_at_utc: datetime
    source: str
    confidence: str
    includes_inflight_usage: bool
    blocked: bool
    exhausted: bool

    def __post_init__(self) -> None:
        for value, maximum, code in (
            (self.window_id, 128, "invalid_usage_window_id"),
            (self.budget_key, 128, "invalid_usage_budget_key"),
            (self.source, 64, "invalid_usage_source"),
        ):
            if not isinstance(value, str) or not 1 <= len(value) <= maximum:
                raise SelectionError(code)
            if any(ord(character) < 32 for character in value):
                raise SelectionError(code)
        if (
            not isinstance(self.applies_to_model_ids, tuple)
            or not isinstance(self.applies_to_model_roles, tuple)
            or len(self.applies_to_model_ids) > 64
            or len(self.applies_to_model_roles) > 16
        ):
            raise SelectionError("invalid_usage_model_scope")
        for item in (*self.applies_to_model_ids, *self.applies_to_model_roles):
            if not isinstance(item, str) or not 1 <= len(item) <= 128 or any(ord(char) < 32 for char in item):
                raise SelectionError("invalid_usage_model_scope")
        if self.quantity_semantics not in {"remaining", "consumed"}:
            raise SelectionError("invalid_usage_semantics")
        if self.quantity_unit not in {"percent", "tokens", "credits", "requests"}:
            raise SelectionError("invalid_usage_unit")
        if (
            isinstance(self.quantity_value, bool)
            or not isinstance(self.quantity_value, int)
            or not 0 <= self.quantity_value <= MAX_USAGE_QUANTITY
        ):
            raise SelectionError("invalid_usage_value")
        if self.quantity_unit == "percent" and self.quantity_value > 100:
            raise SelectionError("invalid_usage_value")
        for value, code in ((self.capacity, "invalid_usage_capacity"), (self.absolute_remaining, "invalid_usage_remaining")):
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_USAGE_QUANTITY
            ):
                raise SelectionError(code)
        if self.window_kind not in {"rolling_5h", "rolling_unanchored", "fixed"}:
            raise SelectionError("invalid_usage_window_kind")
        if self.constraint_relation not in {"conjunctive", "alternative"}:
            raise SelectionError("invalid_usage_relation")
        if self.reset_kind is not None and self.reset_kind not in {"rolling", "fixed", "unanchored"}:
            raise SelectionError("invalid_usage_reset_kind")
        _aware(self.observed_at_utc, "invalid_usage_timestamp")
        if self.reset_at_utc is not None:
            _aware(self.reset_at_utc, "invalid_usage_timestamp")
        if self.confidence not in {"verified", "observed", "unknown"}:
            raise SelectionError("invalid_usage_confidence")
        if not isinstance(self.includes_inflight_usage, bool) or not isinstance(self.blocked, bool) or not isinstance(self.exhausted, bool):
            raise SelectionError("invalid_usage_flags")

    def is_fresh(self, now: datetime, *, max_age_seconds: int = 900) -> bool:
        now = _aware(now, "invalid_selection_time")
        if isinstance(max_age_seconds, bool) or not isinstance(max_age_seconds, int) or not 1 <= max_age_seconds <= 86_400:
            raise SelectionError("invalid_usage_freshness")
        age = (now - self.observed_at_utc).total_seconds()
        return 0 <= age <= max_age_seconds

    def usable_for_sp1(self, now: datetime, *, max_age_seconds: int = 900) -> bool:
        now = _aware(now, "invalid_selection_time")
        return (
            self.quantity_semantics == "remaining"
            and self.quantity_value > 0
            and self.window_kind in {"rolling_5h", "fixed"}
            and self.constraint_relation == "conjunctive"
            and self.confidence == "verified"
            and not self.blocked
            and not self.exhausted
            and (self.reset_at_utc is None or self.reset_at_utc > now)
            and self.is_fresh(now, max_age_seconds=max_age_seconds)
        )


def _usage_datetime(value: object) -> datetime:
    if not isinstance(value, str) or not 1 <= len(value) <= 40:
        raise SelectionError("invalid_usage_timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SelectionError("invalid_usage_timestamp") from exc
    return _aware(parsed, "invalid_usage_timestamp")


def _usage_text(value: object, *, maximum: int, code: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum or any(ord(char) < 32 for char in value):
        raise SelectionError(code)
    return value


def normalize_usage_v2(payload: object) -> tuple[LimitWindow, ...] | None:
    """Normalize only schema-2 ``limit_windows``; schema-1 stays unknown."""

    if not isinstance(payload, Mapping):
        raise SelectionError("invalid_usage_payload")
    version = payload.get("schema_version", 1)
    if version == 1:
        return None
    if version != 2 or set(payload) - {"schema_version", "limit_windows"}:
        raise SelectionError("invalid_usage_payload")
    raw_windows = payload.get("limit_windows")
    if not isinstance(raw_windows, list) or len(raw_windows) > MAX_USAGE_WINDOWS:
        raise SelectionError("invalid_usage_windows")
    windows: list[LimitWindow] = []
    allowed = {
        "window_id", "budget_key", "applies_to_model_ids", "applies_to_model_roles",
        "quantity_semantics", "quantity_unit", "quantity_value", "capacity", "absolute_remaining",
        "window_kind", "constraint_relation", "reset_at_utc", "reset_kind", "observed_at_utc",
        "source", "confidence", "includes_inflight_usage", "blocked", "exhausted",
    }
    for raw in raw_windows:
        if not isinstance(raw, Mapping) or set(raw) - allowed:
            raise SelectionError("invalid_usage_window")
        required = {
            "window_id", "budget_key", "quantity_semantics", "quantity_unit", "quantity_value",
            "window_kind", "constraint_relation", "observed_at_utc", "source", "confidence",
            "includes_inflight_usage", "blocked", "exhausted",
        }
        if not required.issubset(raw):
            raise SelectionError("invalid_usage_window")
        model_ids = raw.get("applies_to_model_ids", [])
        model_roles = raw.get("applies_to_model_roles", [])
        if not isinstance(model_ids, list) or not isinstance(model_roles, list):
            raise SelectionError("invalid_usage_model_scope")
        windows.append(LimitWindow(
            _usage_text(raw["window_id"], maximum=128, code="invalid_usage_window_id"),
            _usage_text(raw["budget_key"], maximum=128, code="invalid_usage_budget_key"),
            tuple(_usage_text(item, maximum=128, code="invalid_usage_model_scope") for item in model_ids),
            tuple(_usage_text(item, maximum=128, code="invalid_usage_model_scope") for item in model_roles),
            raw["quantity_semantics"], raw["quantity_unit"], raw["quantity_value"],
            raw.get("capacity"), raw.get("absolute_remaining"), raw["window_kind"],
            raw["constraint_relation"],
            _usage_datetime(raw["reset_at_utc"]) if raw.get("reset_at_utc") is not None else None,
            raw.get("reset_kind"), _usage_datetime(raw["observed_at_utc"]),
            _usage_text(raw["source"], maximum=64, code="invalid_usage_source"), raw["confidence"],
            raw["includes_inflight_usage"], raw["blocked"], raw["exhausted"],
        ))
    return tuple(windows)


def usage_windows_usable_for_sp1(
    windows: Sequence[LimitWindow],
    now: datetime,
    *,
    max_age_seconds: int = 900,
) -> bool:
    """Require all relevant windows; ambiguous alternatives fail closed."""

    if (
        not windows
        or any(window.constraint_relation != "conjunctive" for window in windows)
        or not any(window.window_kind == "rolling_5h" for window in windows)
    ):
        return False
    return all(window.usable_for_sp1(now, max_age_seconds=max_age_seconds) for window in windows)


@dataclass(frozen=True, slots=True)
class FairnessRecord:
    """Private ledger state; it is never returned in a public preview."""

    service_micro: int
    capacity_weight_micro: int
    last_updated: datetime
    last_selected: datetime | None = None

    def __post_init__(self) -> None:
        if (
            isinstance(self.service_micro, bool)
            or not isinstance(self.service_micro, int)
            or not 0 <= self.service_micro <= MAX_SERVICE_MICRO
        ):
            raise SelectionError("invalid_fairness_service")
        if (
            isinstance(self.capacity_weight_micro, bool)
            or not isinstance(self.capacity_weight_micro, int)
            or not 0 <= self.capacity_weight_micro <= MAX_SERVICE_MICRO
        ):
            raise SelectionError("invalid_fairness_capacity")
        _aware(self.last_updated, "invalid_fairness_timestamp")
        if self.last_selected is not None:
            _aware(self.last_selected, "invalid_fairness_timestamp")

    def decayed_service(self, now: datetime) -> int:
        """Return deterministic fixed-point service with a seven-day half-life."""

        now = _aware(now, "invalid_selection_time")
        elapsed = max(0, int((now - self.last_updated).total_seconds()))
        periods, remainder = divmod(elapsed, HALF_LIFE_SECONDS)
        if periods >= 64:
            return 0
        value = self.service_micro
        for _ in range(periods):
            value //= 2
        # Linear interpolation is intentionally fixed-point and bounds the
        # remainder between the two exact half-life anchor points.
        factor = MICRO - (remainder * MICRO // (2 * HALF_LIFE_SECONDS))
        return value * factor // MICRO

    def normalized_service(self, now: datetime) -> int:
        capacity = max(self.capacity_weight_micro, 1)
        return min(MAX_SERVICE_MICRO, self.decayed_service(now) * MICRO // capacity)


@dataclass(frozen=True, slots=True)
class FairnessLedger:
    """Immutable preview view over opaque account fairness records."""

    records: Mapping[str, FairnessRecord]

    def __post_init__(self) -> None:
        object.__setattr__(self, "records", MappingProxyType(dict(self.records)))

    def normalized_service(self, account_key: str, now: datetime) -> int:
        record = self.records.get(account_key)
        if record is not None:
            return record.normalized_service(now)
        known = sorted(record.normalized_service(now) for record in self.records.values())
        if not known:
            return 0
        return known[(len(known) - 1) // 2]

    def last_selected_epoch(self, account_key: str) -> int:
        record = self.records.get(account_key)
        if record is None or record.last_selected is None:
            return -1
        return int(record.last_selected.timestamp())


@dataclass(frozen=True, slots=True)
class SelectionPolicy:
    """Feature gates for read-only selection preview.

    All gates default off.  Productive admission must provide an explicit
    policy and separately enforce its pilot/credential/safety gates.
    """

    sp0: bool = False
    sp1a: bool = False
    sp1b: bool = False
    sp2: bool = False
    sp3: bool = False

    def __post_init__(self) -> None:
        for value in (self.sp0, self.sp1a, self.sp1b, self.sp2, self.sp3):
            if not isinstance(value, bool):
                raise SelectionError("invalid_selection_policy")


@dataclass(frozen=True, slots=True)
class SelectionCandidate:
    """Candidate input; ``account_key`` is intentionally an opaque private key."""

    agent_id: str
    account_key: str
    model_id: str
    task_kind: TaskKind
    model_role: ModelRole
    enabled: bool = True
    authenticated: bool = True
    account_ready: bool = True
    account_capacity_available: bool = True
    model_capacity_available: bool = True
    lease_available: bool = True
    usage: UsageObservation | None = None
    sp1a_eligible: bool = True
    sp1b_eligible: bool = True
    sp2_eligible: bool = False
    sp1a_bucket: int = 0
    sp1b_bucket: int = 0
    sp2_bucket: int = 0
    repository_affinity: int = 0
    warm_home: bool = False
    recent_failure: bool = False
    rotation_distance: int = 0

    def __post_init__(self) -> None:
        for name in ("agent_id", "account_key", "model_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value or len(value) > 128:
                raise SelectionError("invalid_selection_candidate")
            if any(ord(character) < 32 for character in value):
                raise SelectionError("invalid_selection_candidate")
        for name in ("sp1a_bucket", "sp1b_bucket", "sp2_bucket", "repository_affinity", "rotation_distance"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise SelectionError("invalid_selection_bucket")
        if not isinstance(self.task_kind, TaskKind) or not isinstance(self.model_role, ModelRole):
            raise SelectionError("invalid_selection_candidate")


@dataclass(frozen=True, slots=True)
class SelectionResult:
    agent_id: str
    model_id: str
    band: SelectionBand
    fairness_micro: int


@dataclass(frozen=True, slots=True)
class SelectionPreview:
    selected: SelectionResult | None
    eligible_count: int
    exclusions: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class AdmissionPolicy:
    """Explicit gates required before a selection may execute.

    The default is closed.  These gates describe the contract only; this
    module never reserves a resource, writes state, or starts an agent.
    """

    mode: AdmissionMode = AdmissionMode.OFF
    pilot_repository_allowed: bool = False
    principal_verified: bool = False
    scope_allowed: bool = False
    account_verified: bool = False
    model_verified: bool = False
    reservation_available: bool = False
    execute_enabled: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.mode, AdmissionMode):
            raise SelectionError("invalid_admission_mode")
        for value in (
            self.pilot_repository_allowed,
            self.principal_verified,
            self.scope_allowed,
            self.account_verified,
            self.model_verified,
            self.reservation_available,
            self.execute_enabled,
        ):
            if not isinstance(value, bool):
                raise SelectionError("invalid_admission_policy")

    def missing_gates(self) -> tuple[str, ...]:
        gates = (
            ("pilot_repository", self.pilot_repository_allowed),
            ("principal", self.principal_verified),
            ("scope", self.scope_allowed),
            ("account", self.account_verified),
            ("model", self.model_verified),
            ("reservation", self.reservation_available),
            ("execute", self.execute_enabled),
        )
        return tuple(name for name, enabled in gates if not enabled)


@dataclass(frozen=True, slots=True)
class AdmissionPreview:
    """Secret-free result of binding a selection preview to admission gates."""

    selection: SelectionPreview
    mode: AdmissionMode
    planned: bool
    executable: bool
    reason: str
    missing_gates: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.selection, SelectionPreview) or not isinstance(self.mode, AdmissionMode):
            raise SelectionError("invalid_admission_preview")
        if not isinstance(self.planned, bool) or not isinstance(self.executable, bool):
            raise SelectionError("invalid_admission_preview")
        if not isinstance(self.reason, str) or not self.reason:
            raise SelectionError("invalid_admission_preview")
        if not isinstance(self.missing_gates, tuple) or any(
            not isinstance(gate, str) or not gate for gate in self.missing_gates
        ):
            raise SelectionError("invalid_admission_preview")
        if self.executable and not self.planned:
            raise SelectionError("invalid_admission_preview")


def eligibility_reason(candidate: SelectionCandidate) -> str | None:
    if not candidate.enabled:
        return "disabled"
    if not candidate.authenticated:
        return "unauthenticated"
    if not candidate.account_ready:
        return "account_unready"
    if not candidate.account_capacity_available:
        return "account_capacity"
    if not candidate.model_capacity_available:
        return "model_capacity"
    if not candidate.lease_available:
        return "lease_busy"
    if candidate.task_kind is not TaskKind.SIMPLE and candidate.model_role is ModelRole.SECONDARY_SIMPLE:
        return "secondary_requires_simple_task"
    return None


def _band(candidate: SelectionCandidate, policy: SelectionPolicy, now: datetime) -> SelectionBand | None:
    if policy.sp0 and candidate.usage is not None and candidate.usage.is_passive_sp0_due(now):
        return SelectionBand.SP0
    if policy.sp1a and candidate.sp1a_eligible:
        return SelectionBand.SP1A
    if policy.sp1b and candidate.sp1b_eligible:
        return SelectionBand.SP1B
    if (
        policy.sp2
        and candidate.sp2_eligible
        and candidate.task_kind is TaskKind.SIMPLE
        and candidate.model_role is ModelRole.SECONDARY_SIMPLE
    ):
        return SelectionBand.SP2
    if policy.sp3:
        return SelectionBand.SP3
    return None


def _candidate_key(
    candidate: SelectionCandidate,
    band: SelectionBand,
    ledger: FairnessLedger,
    now: datetime,
) -> tuple[int, int, int, int, int, int, int, int, str, str]:
    if band is SelectionBand.SP0 and candidate.usage is not None:
        due_since = int(candidate.usage.observed_at.timestamp())
    else:
        due_since = 2**63 - 1
    bucket = {
        SelectionBand.SP1A: candidate.sp1a_bucket,
        SelectionBand.SP1B: candidate.sp1b_bucket,
        SelectionBand.SP2: candidate.sp2_bucket,
    }.get(band, 0)
    return (
        _BAND_RANK[band],
        due_since,
        bucket,
        ledger.normalized_service(candidate.account_key, now),
        ledger.last_selected_epoch(candidate.account_key),
        -candidate.repository_affinity,
        -int(candidate.warm_home),
        int(candidate.recent_failure),
        candidate.rotation_distance,
        candidate.agent_id,
    )


def preview_selection(
    candidates: Sequence[SelectionCandidate],
    *,
    policy: SelectionPolicy,
    now: datetime,
    ledger: FairnessLedger | None = None,
) -> SelectionPreview:
    """Build a deterministic, non-mutating selection preview."""

    now = _aware(now, "invalid_selection_time")
    ledger = ledger or FairnessLedger({})
    eligible: list[tuple[tuple[object, ...], SelectionCandidate, SelectionBand]] = []
    exclusions: list[tuple[str, str]] = []
    for candidate in candidates:
        reason = eligibility_reason(candidate)
        if reason is not None:
            exclusions.append((candidate.agent_id, reason))
            continue
        band = _band(candidate, policy, now)
        if band is None:
            exclusions.append((candidate.agent_id, "feature_disabled"))
            continue
        eligible.append((_candidate_key(candidate, band, ledger, now), candidate, band))
    if not eligible:
        return SelectionPreview(None, 0, tuple(exclusions))
    _, candidate, band = min(eligible, key=lambda item: item[0])
    return SelectionPreview(
        SelectionResult(
            candidate.agent_id,
            candidate.model_id,
            band,
            ledger.normalized_service(candidate.account_key, now),
        ),
        len(eligible),
        tuple(exclusions),
    )


def preview_selection_admission(
    candidates: Sequence[SelectionCandidate],
    *,
    selection_policy: SelectionPolicy,
    admission_policy: AdmissionPolicy,
    now: datetime,
    ledger: FairnessLedger | None = None,
) -> AdmissionPreview:
    """Bind a deterministic selection preview to explicit admission gates.

    ``shadow`` produces a plan for comparison but is never executable.
    ``enforced`` is executable only when every gate is present.  ``off`` and
    all incomplete enforced plans remain closed.  No input or ledger state is
    mutated, and the public result contains no account key.
    """

    selection = preview_selection(
        candidates,
        policy=selection_policy,
        now=now,
        ledger=ledger,
    )
    missing = admission_policy.missing_gates()
    if admission_policy.mode is AdmissionMode.OFF:
        return AdmissionPreview(selection, admission_policy.mode, False, False, "admission_disabled", missing)
    if selection.selected is None:
        return AdmissionPreview(selection, admission_policy.mode, False, False, "no_eligible_candidate", missing)
    if admission_policy.mode is AdmissionMode.SHADOW:
        return AdmissionPreview(selection, admission_policy.mode, True, False, "shadow_only", missing)
    if missing:
        return AdmissionPreview(selection, admission_policy.mode, False, False, "admission_gate_blocked", missing)
    return AdmissionPreview(selection, admission_policy.mode, True, True, "admitted", ())
