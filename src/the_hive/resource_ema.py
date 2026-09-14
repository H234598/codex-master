from __future__ import annotations

import json
import math
from dataclasses import dataclass, replace
from typing import Literal


SCHEMA_NAME = "ResourceEMAAdmissionV1"
SCHEMA_VERSION = 1
MAX_SNAPSHOT_BYTES = 64 * 1024
MAX_METRICS = 32
_MAX_MONOTONIC_NS = (1 << 63) - 1

MetricFamily = Literal["cpu", "io", "thermal", "gpu", "memory", "vram"]
Direction = Literal["high", "low"]
InterlockReason = Literal[
    "gap_exceeded",
    "gpu_device_lost",
    "invalid_evidence",
    "missing_evidence",
    "oom_event",
    "required_device_lost",
    "stale_evidence",
    "thermal_critical",
    "time_regression",
]

_INTERLOCK_REASONS = frozenset(
    {
        "gap_exceeded",
        "gpu_device_lost",
        "invalid_evidence",
        "missing_evidence",
        "oom_event",
        "required_device_lost",
        "stale_evidence",
        "thermal_critical",
        "time_regression",
    }
)
_IMMEDIATE_INTERLOCK_REASONS = frozenset(
    {"gpu_device_lost", "oom_event", "required_device_lost", "thermal_critical"}
)
_THERMAL_ROLES = frozenset(
    {
        "thermal_acpi_zone",
        "thermal_cpu_package",
        "thermal_gpu_edge",
        "thermal_gpu_hotspot",
    }
)

# role: family, direction, tau, enter, release, admission enabled
_FIXED_POLICIES: dict[
    str,
    tuple[MetricFamily, Direction, float | None, float | None, float | None, bool],
] = {
    "cpu_busy": ("cpu", "high", 30.0, 90.0, 85.0, True),
    "cpu_load_per_core": ("cpu", "high", 30.0, 1.75, 1.50, True),
    "gpu_queue_percent": ("gpu", "high", 20.0, 90.0, 85.0, True),
    "gpu_utilization": ("gpu", "high", 20.0, 90.0, 85.0, True),
    "io_iops_capacity_percent": ("io", "high", 15.0, 90.0, 85.0, True),
    "io_iops_rate": ("io", "high", 15.0, None, None, False),
    "io_psi_full_avg10": ("io", "high", 15.0, 85.0, 80.0, True),
    "io_psi_full_avg60": ("io", "high", 15.0, 80.0, 75.0, True),
    "io_psi_some_avg10": ("io", "high", 15.0, 95.0, 90.0, True),
    "io_queue_percent": ("io", "high", 15.0, 90.0, 85.0, True),
    "memory_available_mib": ("memory", "low", None, 7168.0, 8192.0, True),
    "vram_used_percent": ("vram", "high", None, 90.0, 85.0, True),
}


class ResourceEMAError(ValueError):
    """Data-sparse contract failure for ResourceEMAAdmissionV1."""


def _invalid() -> None:
    raise ResourceEMAError("resource_ema_invalid")


def _is_finite_number(value: object) -> bool:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    try:
        return math.isfinite(float(value))
    except (OverflowError, ValueError):
        return False


def _number(value: object) -> float:
    if not _is_finite_number(value):
        _invalid()
    try:
        return float(value)
    except (OverflowError, ValueError):
        _invalid()


def _optional_number(value: object) -> float | None:
    return None if value is None else _number(value)


def _is_timestamp(value: object) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= _MAX_MONOTONIC_NS
    )


def _timestamp(value: object) -> int:
    if not _is_timestamp(value):
        _invalid()
    assert isinstance(value, int)
    return value


def _same_number(left: float | None, right: float | None) -> bool:
    if left is None or right is None:
        return left is right
    return left == right


@dataclass(frozen=True, slots=True)
class MetricPolicy:
    role: str
    family: MetricFamily
    direction: Direction
    tau_seconds: float | None
    enter_threshold: float | None
    release_threshold: float | None
    critical_threshold: float | None
    admission_enabled: bool

    def __post_init__(self) -> None:
        if not isinstance(self.role, str):
            _invalid()
        if not isinstance(self.family, str) or self.family not in {
            "cpu",
            "io",
            "thermal",
            "gpu",
            "memory",
            "vram",
        }:
            _invalid()
        if (
            not isinstance(self.direction, str)
            or self.direction not in {"high", "low"}
            or type(self.admission_enabled) is not bool
        ):
            _invalid()

        tau = _optional_number(self.tau_seconds)
        enter = _optional_number(self.enter_threshold)
        release = _optional_number(self.release_threshold)
        critical = _optional_number(self.critical_threshold)
        object.__setattr__(self, "tau_seconds", tau)
        object.__setattr__(self, "enter_threshold", enter)
        object.__setattr__(self, "release_threshold", release)
        object.__setattr__(self, "critical_threshold", critical)

        if self.role in _FIXED_POLICIES:
            expected = _FIXED_POLICIES[self.role]
            actual = (self.family, self.direction, tau, enter, release, self.admission_enabled)
            if any(
                not _same_number(actual_value, expected_value)
                if isinstance(actual_value, (float, type(None)))
                else actual_value != expected_value
                for actual_value, expected_value in zip(actual, expected, strict=True)
            ):
                _invalid()
            if critical is not None:
                _invalid()
        elif self.role in _THERMAL_ROLES:
            self._validate_thermal()
        else:
            _invalid()

        if tau is None and self.family not in {"memory", "vram"}:
            _invalid()
        if tau is not None and tau <= 0.0:
            _invalid()
        if self.admission_enabled:
            if enter is None or release is None:
                _invalid()
            if self.direction == "high" and release >= enter:
                _invalid()
            if self.direction == "low" and release <= enter:
                _invalid()
        elif enter is not None or release is not None:
            _invalid()

    def _validate_thermal(self) -> None:
        if (
            self.family != "thermal"
            or self.direction != "high"
            or self.tau_seconds != 15.0
            or not self.admission_enabled
            or self.enter_threshold is None
            or self.release_threshold is None
        ):
            _invalid()
        enter = self.enter_threshold
        release = self.release_threshold
        critical = self.critical_threshold
        five_degree_pair = release == enter - 5.0
        crit_only_pair = (
            critical is not None
            and enter == 0.9 * critical
            and release == 0.8 * critical
        )
        if not five_degree_pair and not crit_only_pair:
            _invalid()
        if critical is not None and enter >= critical:
            _invalid()

    @property
    def max_age_seconds(self) -> float:
        if self.tau_seconds is None:
            return 30.0
        return 2.0 * self.tau_seconds

    @property
    def max_gap_seconds(self) -> float | None:
        if self.tau_seconds is None:
            return None
        return 2.0 * self.tau_seconds

    @property
    def coverage_target_seconds(self) -> float | None:
        return self.tau_seconds


def canonical_policy(role: str) -> MetricPolicy:
    try:
        family, direction, tau, enter, release, enabled = _FIXED_POLICIES[role]
    except (KeyError, TypeError):
        _invalid()
    return MetricPolicy(
        role=role,
        family=family,
        direction=direction,
        tau_seconds=tau,
        enter_threshold=enter,
        release_threshold=release,
        critical_threshold=None,
        admission_enabled=enabled,
    )


def thermal_policy(
    role: str,
    *,
    high: float | None = None,
    crit: float | None = None,
) -> MetricPolicy:
    if role not in _THERMAL_ROLES:
        _invalid()
    high_value = _optional_number(high)
    crit_value = _optional_number(crit)
    if high_value is None and crit_value is None:
        _invalid()
    if high_value is None:
        assert crit_value is not None
        enter = 0.9 * crit_value
        release = 0.8 * crit_value
    elif crit_value is not None and high_value >= crit_value:
        enter = crit_value - 5.0
        release = crit_value - 10.0
    else:
        enter = high_value
        release = high_value - 5.0
    return MetricPolicy(
        role=role,
        family="thermal",
        direction="high",
        tau_seconds=15.0,
        enter_threshold=enter,
        release_threshold=release,
        critical_threshold=crit_value,
        admission_enabled=True,
    )


def _interlock_allowed(policy: MetricPolicy, reason: object) -> bool:
    if not isinstance(reason, str):
        return False
    if reason == "oom_event":
        return policy.family == "memory"
    if reason == "thermal_critical":
        return policy.family == "thermal"
    if reason == "gpu_device_lost":
        return policy.family in {"gpu", "vram"}
    if reason == "required_device_lost":
        return policy.family == "io"
    return reason in {
        "gap_exceeded",
        "invalid_evidence",
        "missing_evidence",
        "stale_evidence",
        "time_regression",
    }


@dataclass(frozen=True, slots=True)
class MetricState:
    policy: MetricPolicy
    raw: float | None
    ema: float | None
    last_observed_monotonic_ns: int | None
    coverage_seconds: float | None
    latched: bool
    interlock_reason: InterlockReason | None

    def __post_init__(self) -> None:
        if not isinstance(self.policy, MetricPolicy) or type(self.latched) is not bool:
            _invalid()
        raw = _optional_number(self.raw)
        ema = _optional_number(self.ema)
        coverage = _optional_number(self.coverage_seconds)
        observed = self.last_observed_monotonic_ns
        if observed is not None:
            observed = _timestamp(observed)
        if self.interlock_reason is not None:
            if (
                not isinstance(self.interlock_reason, str)
                or self.interlock_reason not in _INTERLOCK_REASONS
                or not _interlock_allowed(self.policy, self.interlock_reason)
            ):
                _invalid()
        if raw is None:
            if ema is not None or coverage is not None or self.latched:
                _invalid()
            if observed is not None and self.interlock_reason is None:
                _invalid()
        elif observed is None:
            _invalid()
        if self.policy.tau_seconds is None:
            if ema is not None or coverage is not None:
                _invalid()
        else:
            if raw is not None and (ema is None or coverage is None):
                _invalid()
            if coverage is not None and not 0.0 <= coverage <= self.policy.tau_seconds:
                _invalid()
            if coverage == 0.0 and raw != ema:
                _invalid()
        if not self.policy.admission_enabled and self.latched:
            _invalid()
        if raw is not None and self.policy.admission_enabled:
            decision_value = raw if ema is None else ema
            enter = self.policy.enter_threshold
            release = self.policy.release_threshold
            assert enter is not None and release is not None
            if coverage == 0.0 and self.latched != self._next_latch(
                decision_value, False
            ):
                _invalid()
            if self.policy.direction == "high":
                if self.latched and decision_value <= release:
                    _invalid()
                if not self.latched and decision_value >= enter:
                    _invalid()
            else:
                if self.latched and decision_value >= release:
                    _invalid()
                if not self.latched and decision_value <= enter:
                    _invalid()
        object.__setattr__(self, "raw", raw)
        object.__setattr__(self, "ema", ema)
        object.__setattr__(self, "last_observed_monotonic_ns", observed)
        object.__setattr__(self, "coverage_seconds", coverage)

    @classmethod
    def cold(cls, policy: MetricPolicy) -> MetricState:
        return cls(
            policy=policy,
            raw=None,
            ema=None,
            last_observed_monotonic_ns=None,
            coverage_seconds=None,
            latched=False,
            interlock_reason=None,
        )

    @property
    def role(self) -> str:
        return self.policy.role

    @property
    def tau_seconds(self) -> float | None:
        return self.policy.tau_seconds

    @property
    def enter_threshold(self) -> float | None:
        return self.policy.enter_threshold

    @property
    def release_threshold(self) -> float | None:
        return self.policy.release_threshold

    def _invalidated(self, observed_at_ns: object, reason: InterlockReason) -> MetricState:
        observed = (
            observed_at_ns
            if _is_timestamp(observed_at_ns)
            else None
        )
        return MetricState(
            policy=self.policy,
            raw=None,
            ema=None,
            last_observed_monotonic_ns=observed,
            coverage_seconds=None,
            latched=False,
            interlock_reason=reason,
        )

    def observe(
        self,
        raw: object,
        observed_at_ns: object,
        *,
        interlock: str | None = None,
    ) -> MetricState:
        if (
            not _is_finite_number(raw)
            or not _is_timestamp(observed_at_ns)
            or (interlock is not None and not _interlock_allowed(self.policy, interlock))
        ):
            return self._invalidated(observed_at_ns, "invalid_evidence")

        value = float(raw)
        assert isinstance(observed_at_ns, int)
        observed = observed_at_ns
        delta_seconds: float | None = None
        if self.last_observed_monotonic_ns is not None:
            delta_ns = observed - self.last_observed_monotonic_ns
            if delta_ns <= 0:
                return self._invalidated(observed, "time_regression")
            max_gap = self.policy.max_gap_seconds
            if max_gap is not None and delta_ns > int(max_gap * 1_000_000_000):
                return self._invalidated(observed, "gap_exceeded")
            delta_seconds = delta_ns / 1_000_000_000

        if self.policy.tau_seconds is None:
            ema = None
            coverage = None
            history_latched = self.latched
            decision_value = value
        elif self.ema is None:
            ema = value
            coverage = 0.0
            history_latched = False
            decision_value = ema
        else:
            assert delta_seconds is not None
            alpha = -math.expm1(-delta_seconds / self.policy.tau_seconds)
            ema = (1.0 - alpha) * self.ema + alpha * value
            coverage = min(
                self.policy.tau_seconds,
                (self.coverage_seconds or 0.0) + delta_seconds,
            )
            history_latched = self.latched
            decision_value = ema

        latched = self._next_latch(decision_value, history_latched)
        reason: str | None = interlock
        critical = self.policy.critical_threshold
        if critical is not None and value >= critical:
            reason = "thermal_critical"
        return MetricState(
            policy=self.policy,
            raw=value,
            ema=ema,
            last_observed_monotonic_ns=observed,
            coverage_seconds=coverage,
            latched=latched,
            interlock_reason=reason,
        )

    def _next_latch(self, value: float, was_latched: bool) -> bool:
        if not self.policy.admission_enabled:
            return False
        enter = self.policy.enter_threshold
        release = self.policy.release_threshold
        assert enter is not None and release is not None
        if self.policy.direction == "high":
            if was_latched:
                return value > release
            return value >= enter
        if was_latched:
            return value < release
        return value <= enter

    def with_interlock(self, reason: str) -> MetricState:
        if (
            not isinstance(reason, str)
            or reason not in _INTERLOCK_REASONS
            or not _interlock_allowed(self.policy, reason)
        ):
            _invalid()
        return replace(self, interlock_reason=reason)

    def effective_interlock(self, now_ns: int) -> InterlockReason | None:
        now = _timestamp(now_ns)
        if self.interlock_reason is not None:
            return self.interlock_reason
        if self.last_observed_monotonic_ns is None:
            return "missing_evidence"
        if now < self.last_observed_monotonic_ns:
            return "time_regression"
        age_ns = now - self.last_observed_monotonic_ns
        if age_ns > int(self.policy.max_age_seconds * 1_000_000_000):
            return "stale_evidence"
        return None

    def age_seconds(self, now_ns: int) -> float | None:
        now = _timestamp(now_ns)
        if self.last_observed_monotonic_ns is None:
            return None
        return max(0.0, (now - self.last_observed_monotonic_ns) / 1_000_000_000)


@dataclass(frozen=True, slots=True)
class AdmissionDecision:
    blocked: bool
    normal_blocked_roles: tuple[str, ...]
    interlocks: tuple[tuple[str, InterlockReason], ...]


@dataclass(frozen=True, slots=True)
class ResourceEMAAdmissionV1:
    metrics: tuple[MetricState, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.metrics, tuple) or len(self.metrics) > MAX_METRICS:
            _invalid()
        if any(not isinstance(metric, MetricState) for metric in self.metrics):
            _invalid()
        ordered = tuple(sorted(self.metrics, key=lambda metric: metric.role))
        roles = tuple(metric.role for metric in ordered)
        if len(set(roles)) != len(roles):
            _invalid()
        object.__setattr__(self, "metrics", ordered)

    @classmethod
    def cold(cls, policies: tuple[MetricPolicy, ...]) -> ResourceEMAAdmissionV1:
        if not isinstance(policies, tuple) or any(
            not isinstance(policy, MetricPolicy) for policy in policies
        ):
            _invalid()
        return cls(tuple(MetricState.cold(policy) for policy in policies))

    def metric(self, role: str) -> MetricState:
        for metric in self.metrics:
            if metric.role == role:
                return metric
        _invalid()

    def _replace_metric(self, updated: MetricState) -> ResourceEMAAdmissionV1:
        return ResourceEMAAdmissionV1(
            tuple(updated if metric.role == updated.role else metric for metric in self.metrics)
        )

    def observe(
        self,
        role: str,
        raw: object,
        observed_at_ns: object,
        *,
        interlock: str | None = None,
    ) -> ResourceEMAAdmissionV1:
        return self._replace_metric(
            self.metric(role).observe(raw, observed_at_ns, interlock=interlock)
        )

    def signal_interlock(self, role: str, reason: str) -> ResourceEMAAdmissionV1:
        return self._replace_metric(self.metric(role).with_interlock(reason))

    def decision(self, now_ns: int) -> AdmissionDecision:
        now = _timestamp(now_ns)
        normal = tuple(
            metric.role
            for metric in self.metrics
            if metric.policy.admission_enabled and metric.latched
        )
        interlocks = tuple(
            (metric.role, reason)
            for metric in self.metrics
            if (reason := metric.effective_interlock(now)) is not None
            and (
                metric.policy.admission_enabled
                or reason in _IMMEDIATE_INTERLOCK_REASONS
            )
        )
        return AdmissionDecision(
            blocked=bool(normal or interlocks),
            normal_blocked_roles=normal,
            interlocks=interlocks,
        )

    def telemetry(self, now_ns: int) -> tuple[dict[str, object], ...]:
        now = _timestamp(now_ns)
        records: list[dict[str, object]] = []
        for metric in self.metrics:
            reason = metric.effective_interlock(now)
            records.append(
                {
                    "age_seconds": metric.age_seconds(now),
                    "coverage": {
                        "seconds": metric.coverage_seconds,
                        "target_seconds": metric.policy.coverage_target_seconds,
                    },
                    "ema": metric.ema,
                    "hysteresis": {"state": "blocked" if metric.latched else "clear"},
                    "interlock": {"active": reason is not None, "reason": reason},
                    "raw": metric.raw,
                    "role": metric.role,
                    "tau_seconds": metric.tau_seconds,
                    "threshold": {
                        "critical": metric.policy.critical_threshold,
                        "enter": metric.enter_threshold,
                        "release": metric.release_threshold,
                    },
                }
            )
        return tuple(records)

    def to_json(self) -> bytes:
        metrics: list[dict[str, object]] = []
        for metric in self.metrics:
            policy = metric.policy
            metrics.append(
                {
                    "admission_enabled": policy.admission_enabled,
                    "coverage_seconds": metric.coverage_seconds,
                    "critical_threshold": policy.critical_threshold,
                    "direction": policy.direction,
                    "ema": metric.ema,
                    "enter_threshold": policy.enter_threshold,
                    "family": policy.family,
                    "interlock": {
                        "active": metric.interlock_reason is not None,
                        "reason": metric.interlock_reason,
                    },
                    "last_observed_monotonic_ns": metric.last_observed_monotonic_ns,
                    "latched": metric.latched,
                    "raw": metric.raw,
                    "release_threshold": policy.release_threshold,
                    "role": metric.role,
                    "tau_seconds": policy.tau_seconds,
                }
            )
        try:
            encoded = json.dumps(
                {"metrics": metrics, "schema": SCHEMA_NAME, "schema_version": SCHEMA_VERSION},
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        except (TypeError, ValueError, OverflowError, RecursionError):
            _invalid()
        if len(encoded) > MAX_SNAPSHOT_BYTES:
            _invalid()
        return encoded

    @classmethod
    def from_json(cls, payload: bytes) -> ResourceEMAAdmissionV1:
        if not isinstance(payload, bytes) or not payload or len(payload) > MAX_SNAPSHOT_BYTES:
            _invalid()

        def object_pairs(pairs: list[tuple[object, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in pairs:
                if not isinstance(key, str) or key in result:
                    _invalid()
                result[key] = value
            return result

        def reject_constant(_value: str) -> None:
            _invalid()

        try:
            document = json.loads(
                payload.decode("utf-8"),
                object_pairs_hook=object_pairs,
                parse_constant=reject_constant,
            )
        except (ValueError, OverflowError, RecursionError):
            _invalid()
        if not isinstance(document, dict) or set(document) != {
            "metrics",
            "schema",
            "schema_version",
        }:
            _invalid()
        if document["schema"] != SCHEMA_NAME or document["schema_version"] != SCHEMA_VERSION:
            _invalid()
        if type(document["schema_version"]) is not int:
            _invalid()
        raw_metrics = document["metrics"]
        if not isinstance(raw_metrics, list) or len(raw_metrics) > MAX_METRICS:
            _invalid()
        try:
            return cls(tuple(cls._metric_from_document(item) for item in raw_metrics))
        except (ValueError, OverflowError):
            _invalid()

    @staticmethod
    def _metric_from_document(item: object) -> MetricState:
        fields = {
            "admission_enabled",
            "coverage_seconds",
            "critical_threshold",
            "direction",
            "ema",
            "enter_threshold",
            "family",
            "interlock",
            "last_observed_monotonic_ns",
            "latched",
            "raw",
            "release_threshold",
            "role",
            "tau_seconds",
        }
        if not isinstance(item, dict) or set(item) != fields:
            _invalid()
        role = item["role"]
        family = item["family"]
        direction = item["direction"]
        enabled = item["admission_enabled"]
        latched = item["latched"]
        if (
            not isinstance(role, str)
            or not isinstance(family, str)
            or family not in {"cpu", "io", "thermal", "gpu", "memory", "vram"}
            or not isinstance(direction, str)
            or direction not in {"high", "low"}
            or type(enabled) is not bool
            or type(latched) is not bool
        ):
            _invalid()
        interlock = item["interlock"]
        if not isinstance(interlock, dict) or set(interlock) != {"active", "reason"}:
            _invalid()
        active = interlock["active"]
        reason = interlock["reason"]
        if type(active) is not bool or (reason is not None and not isinstance(reason, str)):
            _invalid()
        if active != (reason is not None):
            _invalid()
        observed_value = item["last_observed_monotonic_ns"]
        observed = None if observed_value is None else _timestamp(observed_value)
        policy = MetricPolicy(
            role=role,
            family=family,
            direction=direction,
            tau_seconds=_optional_number(item["tau_seconds"]),
            enter_threshold=_optional_number(item["enter_threshold"]),
            release_threshold=_optional_number(item["release_threshold"]),
            critical_threshold=_optional_number(item["critical_threshold"]),
            admission_enabled=enabled,
        )
        return MetricState(
            policy=policy,
            raw=_optional_number(item["raw"]),
            ema=_optional_number(item["ema"]),
            last_observed_monotonic_ns=observed,
            coverage_seconds=_optional_number(item["coverage_seconds"]),
            latched=latched,
            interlock_reason=reason,
        )


__all__ = [
    "MAX_SNAPSHOT_BYTES",
    "AdmissionDecision",
    "MetricPolicy",
    "MetricState",
    "ResourceEMAAdmissionV1",
    "ResourceEMAError",
    "canonical_policy",
    "thermal_policy",
]
