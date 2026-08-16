"""Pure, immutable resource snapshot models and projections."""

from __future__ import annotations

import json
import math
import os
import re
import selectors
import stat
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Callable, Literal, Protocol
from uuid import UUID

from codex_master.hive.state import HiveStateError, HiveStateStore


_SCHEMA_VERSION = 1
_FRESHNESS_MAX_AGE = timedelta(seconds=3)
_DIMENSIONS = frozenset(("cpu", "io", "memory"))
_TRENDS = frozenset(("rising", "stable", "falling"))
_BOTTLENECKS = frozenset(("cpu", "io", "memory", "thermal", "cgroup", "unknown"))
_THERMAL_STATES = frozenset(("warming_up", "no_valid_sensors", "ready", "monitor_unavailable"))
_CGROUP_STATES = frozenset(("ready", "unavailable", "preflight_failed"))
_GATE_STATES = frozenset(("ready", "blocked"))
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_PROFILE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
_SENSOR_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_:-]{0,127}$")
_RESOURCE_DOCUMENT_MAX_BYTES = 64 * 1024
_KERNEL_INPUT_MAX_BYTES = 64 * 1024
_PSI_INPUT_MAX_BYTES = 4 * 1024
_BOOT_ID_MAX_BYTES = 128
_SENSORS_STDOUT_MAX_BYTES = 512 * 1024
_SENSORS_STDERR_MAX_BYTES = 16 * 1024
_SENSORS_TIMEOUT_SECONDS = 1.0
_ONE_SECOND_NS = 1_000_000_000
_MAX_SAMPLE_BUCKETS = 60
_MIN_COMPLETE_SAMPLES = 10
_DECIMAL = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")
_RESOURCE_SNAPSHOT_PATH = PurePosixPath("resources/resource-snapshot-v1.json")
_THERMAL_POLICY_PATH = PurePosixPath("resources/thermal-policy-v1.json")
_THERMAL_POLICY_FIELDS = frozenset(("schema_version", "sensor_thresholds"))
_SNAPSHOT_FIELDS = frozenset(
    (
        "schema_version",
        "boot_id",
        "generation",
        "observed_at_utc",
        "observed_monotonic_ns",
        "freshness",
        "gate_state",
        "reason_codes",
        "current",
        "mean_1m",
        "mean_10m",
        "peak_10m",
        "normalized_pressure",
        "normalized_headroom",
        "trend",
        "bottleneck",
        "preferred_profiles",
        "avoid_profiles",
        "confidence",
        "cgroup_state",
        "thermal_state",
    )
)


class ResourceSnapshotError(ValueError):
    """A data-sparse resource snapshot validation error."""


@dataclass(frozen=True, slots=True)
class ResourceInputPaths:
    """Fixed kernel input allowlist; callers cannot select host paths."""

    loadavg: Path = Path("/proc/loadavg")
    meminfo: Path = Path("/proc/meminfo")
    stat: Path = Path("/proc/stat")
    psi_cpu: Path = Path("/proc/pressure/cpu")
    psi_io: Path = Path("/proc/pressure/io")
    psi_memory: Path = Path("/proc/pressure/memory")
    boot_id: Path = Path("/proc/sys/kernel/random/boot_id")

    def __post_init__(self) -> None:
        expected = (
            Path("/proc/loadavg"),
            Path("/proc/meminfo"),
            Path("/proc/stat"),
            Path("/proc/pressure/cpu"),
            Path("/proc/pressure/io"),
            Path("/proc/pressure/memory"),
            Path("/proc/sys/kernel/random/boot_id"),
        )
        values = (
            self.loadavg,
            self.meminfo,
            self.stat,
            self.psi_cpu,
            self.psi_io,
            self.psi_memory,
            self.boot_id,
        )
        if values != expected:
            _invalid()


class ResourceInputBackend(Protocol):
    def read_private_kernel_bytes(self, path: Path, *, max_bytes: int) -> bytes: ...

    def run_sensors_json(
        self,
        *,
        argv: tuple[str, str],
        environment: Mapping[str, str],
        stdin_closed: bool,
        timeout_seconds: float,
        max_stdout_bytes: int,
        max_stderr_bytes: int,
    ) -> bytes: ...


@dataclass(frozen=True, slots=True)
class ResourceClocks:
    now_utc: Callable[[], datetime]
    monotonic_ns: Callable[[], int]

    def __post_init__(self) -> None:
        if not callable(self.now_utc) or not callable(self.monotonic_ns):
            _invalid()


@dataclass(frozen=True, slots=True)
class ThermalCandidate:
    chip: str
    adapter: str
    label: str
    high: float | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "chip", _normalize_sensor_component(self.chip))
        object.__setattr__(self, "adapter", _normalize_sensor_component(self.adapter))
        object.__setattr__(self, "label", _normalize_sensor_component(self.label))
        if self.high is not None:
            object.__setattr__(self, "high", _require_temperature(self.high))

    @property
    def sensor_id(self) -> str:
        return f"{self.chip}:{self.adapter}:{self.label}"


@dataclass(frozen=True, slots=True)
class ResourceSampleV1:
    boot_id: str
    observed_at_utc: datetime
    observed_monotonic_ns: int
    current: Mapping[str, float]
    cgroup_state: Literal["unavailable"]
    thermal_state: Literal["warming_up", "no_valid_sensors", "ready", "monitor_unavailable"]
    thermal_policy: ThermalPolicyV1 | None

    def __post_init__(self) -> None:
        object.__setattr__(self, "boot_id", _require_canonical_boot_id(self.boot_id))
        object.__setattr__(self, "observed_at_utc", _require_utc_datetime(self.observed_at_utc))
        object.__setattr__(self, "observed_monotonic_ns", _require_positive_int(self.observed_monotonic_ns))
        object.__setattr__(self, "current", _require_metric_mapping(self.current))
        if self.cgroup_state != "unavailable":
            _invalid()
        object.__setattr__(self, "cgroup_state", "unavailable")
        object.__setattr__(self, "thermal_state", _require_thermal_state(self.thermal_state))
        if self.thermal_policy is not None and not isinstance(self.thermal_policy, ThermalPolicyV1):
            _invalid()


class HostResourceInputBackend:
    """Production adapter for the fixed allowlist; normal tests inject fakes."""

    _allowed_kernel_paths = frozenset(
        {
            Path("/proc/loadavg"),
            Path("/proc/meminfo"),
            Path("/proc/stat"),
            Path("/proc/pressure/cpu"),
            Path("/proc/pressure/io"),
            Path("/proc/pressure/memory"),
            Path("/proc/sys/kernel/random/boot_id"),
        }
    )

    def __init__(self, *, monotonic_seconds: Callable[[], float]) -> None:
        if not callable(monotonic_seconds):
            _invalid()
        self._monotonic_seconds = monotonic_seconds

    def read_private_kernel_bytes(self, path: Path, *, max_bytes: int) -> bytes:
        if path not in self._allowed_kernel_paths or type(max_bytes) is not int or max_bytes <= 0:
            _monitor_unavailable()
        parent = path.parent
        try:
            parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            before = os.fstat(parent_fd)
            file_fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
            try:
                file_stat = os.fstat(file_fd)
                if not stat.S_ISREG(file_stat.st_mode):
                    _monitor_unavailable()
                data = os.read(file_fd, max_bytes + 1)
            finally:
                os.close(file_fd)
            after = os.fstat(parent_fd)
        except (OSError, ValueError):
            _monitor_unavailable()
        finally:
            try:
                os.close(parent_fd)
            except (OSError, UnboundLocalError):
                pass
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino) or len(data) > max_bytes:
            _monitor_unavailable()
        return data

    def run_sensors_json(
        self,
        *,
        argv: tuple[str, str],
        environment: Mapping[str, str],
        stdin_closed: bool,
        timeout_seconds: float,
        max_stdout_bytes: int,
        max_stderr_bytes: int,
    ) -> bytes:
        if (
            argv != ("/usr/bin/sensors", "-j")
            or dict(environment) != {"LC_ALL": "C", "LANG": "C", "PATH": "/usr/bin:/bin"}
            or stdin_closed is not True
            or timeout_seconds != _SENSORS_TIMEOUT_SECONDS
            or max_stdout_bytes != _SENSORS_STDOUT_MAX_BYTES
            or max_stderr_bytes != _SENSORS_STDERR_MAX_BYTES
        ):
            _thermal_unavailable()
        try:
            process = subprocess.Popen(
                argv,
                close_fds=True,
                env=dict(environment),
                stdin=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                stdout=subprocess.PIPE,
            )
            if process.stdout is None or process.stderr is None:
                _thermal_unavailable()
            buffers = {process.stdout: bytearray(), process.stderr: bytearray()}
            limits = {process.stdout: max_stdout_bytes, process.stderr: max_stderr_bytes}
            deadline = self._monotonic_seconds() + timeout_seconds
            with selectors.DefaultSelector() as selector:
                for stream in buffers:
                    selector.register(stream, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - self._monotonic_seconds()
                    if not math.isfinite(remaining) or remaining <= 0:
                        _thermal_unavailable()
                    for key, _mask in selector.select(remaining):
                        stream = key.fileobj
                        chunk = os.read(stream.fileno(), 8192)
                        if not chunk:
                            selector.unregister(stream)
                            continue
                        buffers[stream].extend(chunk)
                        if len(buffers[stream]) > limits[stream]:
                            _thermal_unavailable()
            remaining = deadline - self._monotonic_seconds()
            if not math.isfinite(remaining) or remaining <= 0 or process.wait(timeout=remaining) != 0:
                _thermal_unavailable()
        except (OSError, subprocess.SubprocessError, ValueError):
            _thermal_unavailable()
        finally:
            if "process" in locals() and process.poll() is None:
                process.kill()
                process.wait()
        return bytes(buffers[process.stdout])


@dataclass(frozen=True, slots=True)
class ThermalPolicyV1:
    """Normalized thermal thresholds, without applet or host configuration."""

    schema_version: int
    sensor_thresholds: Mapping[str, float]

    def __post_init__(self) -> None:
        object.__setattr__(self, "schema_version", _require_schema_version(self.schema_version))
        if not isinstance(self.sensor_thresholds, Mapping) or len(self.sensor_thresholds) > 256:
            _invalid()
        normalized: dict[str, float] = {}
        for sensor, threshold in self.sensor_thresholds.items():
            if not isinstance(sensor, str) or not _SENSOR_IDENTIFIER.fullmatch(sensor):
                _invalid()
            if type(threshold) not in {int, float} or not math.isfinite(threshold) or not 0 < threshold <= 200:
                _invalid()
            normalized[sensor] = float(threshold)
        object.__setattr__(self, "sensor_thresholds", MappingProxyType(normalized))


@dataclass(frozen=True, slots=True)
class TrendAssessmentV1:
    trend: Literal["rising", "stable", "falling"] | None
    confidence: Literal["high", "low"]

    def __post_init__(self) -> None:
        confidence = _require_confidence(self.confidence)
        if confidence == "high" and (
            not isinstance(self.trend, str) or self.trend not in _TRENDS
        ):
            _invalid()
        if confidence == "low" and self.trend is not None:
            _invalid()
        object.__setattr__(self, "confidence", confidence)


@dataclass(frozen=True, slots=True)
class ResourceSnapshotV1:
    schema_version: int
    boot_id: str
    generation: int
    observed_at_utc: datetime
    observed_monotonic_ns: int
    freshness: Literal["fresh"]
    gate_state: Literal["ready", "blocked"]
    reason_codes: tuple[str, ...]
    current: Mapping[str, float]
    mean_1m: Mapping[str, float]
    mean_10m: Mapping[str, float]
    peak_10m: Mapping[str, float]
    normalized_pressure: Mapping[str, int]
    normalized_headroom: Mapping[str, int]
    trend: Mapping[str, Literal["rising", "stable", "falling"] | None]
    bottleneck: Literal["cpu", "io", "memory", "thermal", "cgroup", "unknown"]
    preferred_profiles: tuple[str, ...]
    avoid_profiles: tuple[str, ...]
    confidence: Literal["high", "low"]
    cgroup_state: Literal["ready", "unavailable", "preflight_failed"]
    thermal_state: Literal["warming_up", "no_valid_sensors", "ready", "monitor_unavailable"]

    def __post_init__(self) -> None:
        object.__setattr__(self, "schema_version", _require_schema_version(self.schema_version))
        object.__setattr__(self, "boot_id", _require_canonical_boot_id(self.boot_id))
        object.__setattr__(self, "generation", _require_positive_int(self.generation))
        object.__setattr__(self, "observed_at_utc", _require_utc_datetime(self.observed_at_utc))
        object.__setattr__(self, "observed_monotonic_ns", _require_positive_int(self.observed_monotonic_ns))
        if self.freshness != "fresh":
            _invalid()
        object.__setattr__(self, "gate_state", _require_gate_state(self.gate_state))
        object.__setattr__(self, "reason_codes", _require_identifiers(self.reason_codes, pattern=_IDENTIFIER, maximum=16))
        object.__setattr__(self, "current", _require_metric_mapping(self.current))
        object.__setattr__(self, "mean_1m", _require_metric_mapping(self.mean_1m))
        object.__setattr__(self, "mean_10m", _require_metric_mapping(self.mean_10m))
        object.__setattr__(self, "peak_10m", _require_metric_mapping(self.peak_10m))
        object.__setattr__(self, "normalized_pressure", _require_percentage_mapping(self.normalized_pressure))
        object.__setattr__(self, "normalized_headroom", _require_percentage_mapping(self.normalized_headroom))
        confidence = _require_confidence(self.confidence)
        object.__setattr__(self, "trend", _require_snapshot_trend_mapping(self.trend, confidence))
        object.__setattr__(self, "confidence", confidence)
        object.__setattr__(self, "bottleneck", _require_bottleneck(self.bottleneck))
        object.__setattr__(self, "preferred_profiles", _require_identifiers(self.preferred_profiles, pattern=_PROFILE, maximum=8))
        object.__setattr__(self, "avoid_profiles", _require_identifiers(self.avoid_profiles, pattern=_PROFILE, maximum=8))
        object.__setattr__(self, "cgroup_state", _require_cgroup_state(self.cgroup_state))
        object.__setattr__(self, "thermal_state", _require_thermal_state(self.thermal_state))


@dataclass(frozen=True, slots=True)
class ResourceGateFacts:
    generation: int
    observed_at_utc: datetime
    observed_monotonic_ns: int
    gate_state: str
    reason_codes: tuple[str, ...]
    current: Mapping[str, float]
    normalized_pressure: Mapping[str, int]
    normalized_headroom: Mapping[str, int]
    bottleneck: str
    cgroup_state: str
    thermal_state: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "generation", _require_positive_int(self.generation))
        object.__setattr__(self, "observed_at_utc", _require_utc_datetime(self.observed_at_utc))
        object.__setattr__(self, "observed_monotonic_ns", _require_positive_int(self.observed_monotonic_ns))
        object.__setattr__(self, "gate_state", _require_gate_state(self.gate_state))
        object.__setattr__(self, "reason_codes", _require_identifiers(self.reason_codes, pattern=_IDENTIFIER, maximum=16))
        object.__setattr__(self, "current", _require_metric_mapping(self.current))
        object.__setattr__(self, "normalized_pressure", _require_percentage_mapping(self.normalized_pressure))
        object.__setattr__(self, "normalized_headroom", _require_percentage_mapping(self.normalized_headroom))
        object.__setattr__(self, "bottleneck", _require_bottleneck(self.bottleneck))
        object.__setattr__(self, "cgroup_state", _require_cgroup_state(self.cgroup_state))
        object.__setattr__(self, "thermal_state", _require_thermal_state(self.thermal_state))


@dataclass(frozen=True, slots=True)
class ResourceOperatorStatus:
    schema_version: int
    generation: int
    state: str
    bottleneck: str
    current: Mapping[str, float]
    mean_1m: Mapping[str, float]
    mean_10m: Mapping[str, float]
    peak_10m: Mapping[str, float]
    trend: Mapping[str, Literal["rising", "stable", "falling"]]
    confidence: Literal["high", "low"]
    preferred_profiles: tuple[str, ...]
    avoid_profiles: tuple[str, ...]
    reason_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "schema_version", _require_schema_version(self.schema_version))
        object.__setattr__(self, "generation", _require_positive_int(self.generation))
        object.__setattr__(self, "state", _require_gate_state(self.state))
        object.__setattr__(self, "bottleneck", _require_bottleneck(self.bottleneck))
        object.__setattr__(self, "current", _require_metric_mapping(self.current))
        object.__setattr__(self, "mean_1m", _require_metric_mapping(self.mean_1m))
        object.__setattr__(self, "mean_10m", _require_metric_mapping(self.mean_10m))
        object.__setattr__(self, "peak_10m", _require_metric_mapping(self.peak_10m))
        confidence = _require_confidence(self.confidence)
        object.__setattr__(self, "trend", _require_operator_trend_mapping(self.trend, confidence))
        object.__setattr__(self, "confidence", confidence)
        object.__setattr__(self, "preferred_profiles", _require_identifiers(self.preferred_profiles, pattern=_PROFILE, maximum=8))
        object.__setattr__(self, "avoid_profiles", _require_identifiers(self.avoid_profiles, pattern=_PROFILE, maximum=8))
        object.__setattr__(self, "reason_codes", _require_identifiers(self.reason_codes, pattern=_IDENTIFIER, maximum=16))


@dataclass(frozen=True, slots=True)
class ResourceSchedulerSnapshot:
    schema_version: int
    generation: int
    confidence: Literal["high", "low"]
    normalized_pressure: Mapping[str, int]
    preferred_profiles: tuple[str, ...]
    avoid_profiles: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "schema_version", _require_schema_version(self.schema_version))
        object.__setattr__(self, "generation", _require_positive_int(self.generation))
        object.__setattr__(self, "confidence", _require_confidence(self.confidence))
        object.__setattr__(self, "normalized_pressure", _require_percentage_mapping(self.normalized_pressure))
        object.__setattr__(self, "preferred_profiles", _require_identifiers(self.preferred_profiles, pattern=_PROFILE, maximum=8))
        object.__setattr__(self, "avoid_profiles", _require_identifiers(self.avoid_profiles, pattern=_PROFILE, maximum=8))


def _invalid() -> None:
    raise ResourceSnapshotError("resource_snapshot_invalid")


def _monitor_unavailable() -> None:
    raise ResourceSnapshotError("resource_monitor_unavailable")


def _thermal_unavailable() -> None:
    raise ResourceSnapshotError("temperature_monitor_unavailable")


def _require_positive_int(value: object) -> int:
    if type(value) is not int or value <= 0:
        _invalid()
    return value


def _require_utc_datetime(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta():
        _invalid()
    return value.astimezone(timezone.utc)


def _require_bounded_number(value: object) -> float:
    if type(value) not in {int, float} or not math.isfinite(value) or not 0 <= value <= 100:
        _invalid()
    return float(value)


def _require_temperature(value: object) -> float:
    if type(value) not in {int, float} or not math.isfinite(value) or not 0 < value <= 200:
        _invalid()
    return float(value)


def _normalize_sensor_component(value: object) -> str:
    if not isinstance(value, str) or len(value) > 128:
        _invalid()
    normalized = re.sub(r"[^a-z0-9_-]+", "_", value.strip().lower()).strip("_")
    if not normalized or not _SENSOR_IDENTIFIER.fullmatch(normalized):
        _invalid()
    return normalized


def _require_metric_mapping(value: object) -> Mapping[str, float]:
    if not isinstance(value, Mapping) or set(value) != _DIMENSIONS:
        _invalid()
    return MappingProxyType({dimension: _require_bounded_number(value[dimension]) for dimension in _DIMENSIONS})


def _require_percentage_mapping(value: object) -> Mapping[str, int]:
    if not isinstance(value, Mapping) or set(value) != _DIMENSIONS:
        _invalid()
    normalized: dict[str, int] = {}
    for dimension in _DIMENSIONS:
        item = value[dimension]
        if type(item) is not int or not 0 <= item <= 100:
            _invalid()
        normalized[dimension] = item
    return MappingProxyType(normalized)


def _require_schema_version(value: object) -> int:
    if type(value) is not int or value != _SCHEMA_VERSION:
        _invalid()
    return value


def _require_confidence(value: object) -> Literal["high", "low"]:
    if not isinstance(value, str) or value not in {"high", "low"}:
        _invalid()
    return value  # type: ignore[return-value]


def _require_snapshot_trend_mapping(
    value: object, confidence: Literal["high", "low"]
) -> Mapping[str, Literal["rising", "stable", "falling"] | None]:
    if not isinstance(value, Mapping) or set(value) != _DIMENSIONS:
        _invalid()
    normalized: dict[str, Literal["rising", "stable", "falling"] | None] = {}
    for dimension in _DIMENSIONS:
        item = value[dimension]
        if confidence == "low":
            if item is not None:
                _invalid()
        elif not isinstance(item, str) or item not in _TRENDS:
            _invalid()
        normalized[dimension] = item  # type: ignore[assignment]
    return MappingProxyType(normalized)


def _require_operator_trend_mapping(
    value: object, confidence: Literal["high", "low"]
) -> Mapping[str, Literal["rising", "stable", "falling"]]:
    if confidence == "low":
        if not isinstance(value, Mapping) or value:
            _invalid()
        return MappingProxyType({})
    if not isinstance(value, Mapping) or set(value) != _DIMENSIONS:
        _invalid()
    normalized: dict[str, Literal["rising", "stable", "falling"]] = {}
    for dimension in _DIMENSIONS:
        item = value[dimension]
        if not isinstance(item, str) or item not in _TRENDS:
            _invalid()
        normalized[dimension] = item  # type: ignore[assignment]
    return MappingProxyType(normalized)


def _require_identifiers(value: object, *, pattern: re.Pattern[str], maximum: int) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or len(value) > maximum:
        _invalid()
    if any(not isinstance(item, str) or not pattern.fullmatch(item) for item in value):
        _invalid()
    normalized = tuple(value)
    if len(set(normalized)) != len(normalized):
        _invalid()
    return normalized


def _parse_utc(value: object) -> datetime:
    if not isinstance(value, str):
        _invalid()
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _invalid()
    return _require_utc_datetime(parsed)


def _require_canonical_boot_id(value: object, expected_boot_id: str | None = None) -> str:
    if not isinstance(value, str) or (expected_boot_id is not None and not isinstance(expected_boot_id, str)):
        _invalid()
    try:
        if str(UUID(value)) != value:
            _invalid()
        if expected_boot_id is not None and str(UUID(expected_boot_id)) != expected_boot_id:
            _invalid()
    except ValueError:
        _invalid()
    if expected_boot_id is not None and value != expected_boot_id:
        _invalid()
    return value


def _require_gate_state(value: object) -> Literal["ready", "blocked"]:
    if not isinstance(value, str) or value not in _GATE_STATES:
        _invalid()
    return value  # type: ignore[return-value]


def _require_bottleneck(value: object) -> Literal["cpu", "io", "memory", "thermal", "cgroup", "unknown"]:
    if not isinstance(value, str) or value not in _BOTTLENECKS:
        _invalid()
    return value  # type: ignore[return-value]


def _require_cgroup_state(value: object) -> Literal["ready", "unavailable", "preflight_failed"]:
    if not isinstance(value, str) or value not in _CGROUP_STATES:
        _invalid()
    return value  # type: ignore[return-value]


def _require_thermal_state(value: object) -> Literal["warming_up", "no_valid_sensors", "ready", "monitor_unavailable"]:
    if not isinstance(value, str) or value not in _THERMAL_STATES:
        _invalid()
    return value  # type: ignore[return-value]


def parse_snapshot_document(
    payload: Mapping[str, object], *, now_utc: datetime, expected_boot_id: str
) -> ResourceSnapshotV1:
    """Validate one already-decoded, fresh resource snapshot document."""

    if not isinstance(payload, Mapping) or set(payload) != _SNAPSHOT_FIELDS:
        _invalid()
    now_utc = _require_utc_datetime(now_utc)
    observed_at_utc = _parse_utc(payload["observed_at_utc"])
    if observed_at_utc > now_utc or now_utc - observed_at_utc > _FRESHNESS_MAX_AGE:
        _invalid()

    return ResourceSnapshotV1(
        schema_version=payload["schema_version"],
        boot_id=_require_canonical_boot_id(payload["boot_id"], expected_boot_id),
        generation=payload["generation"],
        observed_at_utc=observed_at_utc,
        observed_monotonic_ns=payload["observed_monotonic_ns"],
        freshness=payload["freshness"],
        gate_state=payload["gate_state"],
        reason_codes=payload["reason_codes"],
        current=payload["current"],
        mean_1m=payload["mean_1m"],
        mean_10m=payload["mean_10m"],
        peak_10m=payload["peak_10m"],
        normalized_pressure=payload["normalized_pressure"],
        normalized_headroom=payload["normalized_headroom"],
        trend=payload["trend"],
        bottleneck=payload["bottleneck"],
        preferred_profiles=payload["preferred_profiles"],
        avoid_profiles=payload["avoid_profiles"],
        confidence=payload["confidence"],
        cgroup_state=payload["cgroup_state"],
        thermal_state=payload["thermal_state"],
    )


def _require_state(value: object) -> HiveStateStore:
    if not isinstance(value, HiveStateStore):
        _invalid()
    return value


def _reject_duplicate_pairs(pairs: list[tuple[object, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if not isinstance(key, str) or key in result:
            _invalid()
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> object:
    _invalid()


def _validate_document_tree(value: object, *, depth: int = 0) -> None:
    if depth > 16:
        _invalid()
    if value is None:
        return
    if isinstance(value, str):
        if len(value) > 128:
            _invalid()
        return
    if type(value) is bool:
        _invalid()
    if type(value) is int:
        return
    if type(value) is float:
        if not math.isfinite(value):
            _invalid()
        return
    if isinstance(value, Mapping):
        if len(value) > 256:
            _invalid()
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 128:
                _invalid()
            _validate_document_tree(item, depth=depth + 1)
        return
    if isinstance(value, list):
        if len(value) > 256:
            _invalid()
        for item in value:
            _validate_document_tree(item, depth=depth + 1)
        return
    _invalid()


def _decode_resource_document(raw: object) -> Mapping[str, object]:
    if type(raw) is not bytes or len(raw) > _RESOURCE_DOCUMENT_MAX_BYTES:
        _invalid()
    try:
        decoded = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        _invalid()
    _validate_document_tree(decoded)
    if not isinstance(decoded, Mapping):
        _invalid()
    return decoded


def _snapshot_from_stored_document(payload: Mapping[str, object]) -> ResourceSnapshotV1:
    if set(payload) != _SNAPSHOT_FIELDS:
        _invalid()
    return ResourceSnapshotV1(
        schema_version=payload["schema_version"],
        boot_id=_require_canonical_boot_id(payload["boot_id"]),
        generation=payload["generation"],
        observed_at_utc=_parse_utc(payload["observed_at_utc"]),
        observed_monotonic_ns=payload["observed_monotonic_ns"],
        freshness=payload["freshness"],
        gate_state=payload["gate_state"],
        reason_codes=payload["reason_codes"],
        current=payload["current"],
        mean_1m=payload["mean_1m"],
        mean_10m=payload["mean_10m"],
        peak_10m=payload["peak_10m"],
        normalized_pressure=payload["normalized_pressure"],
        normalized_headroom=payload["normalized_headroom"],
        trend=payload["trend"],
        bottleneck=payload["bottleneck"],
        preferred_profiles=payload["preferred_profiles"],
        avoid_profiles=payload["avoid_profiles"],
        confidence=payload["confidence"],
        cgroup_state=payload["cgroup_state"],
        thermal_state=payload["thermal_state"],
    )


def _thermal_policy_from_document(payload: Mapping[str, object]) -> ThermalPolicyV1:
    if set(payload) != _THERMAL_POLICY_FIELDS:
        _invalid()
    return ThermalPolicyV1(
        schema_version=payload["schema_version"],
        sensor_thresholds=payload["sensor_thresholds"],
    )


def _snapshot_document(snapshot: ResourceSnapshotV1) -> Mapping[str, object]:
    if not isinstance(snapshot, ResourceSnapshotV1):
        _invalid()
    return {
        "schema_version": snapshot.schema_version,
        "boot_id": snapshot.boot_id,
        "generation": snapshot.generation,
        "observed_at_utc": snapshot.observed_at_utc.isoformat().replace("+00:00", "Z"),
        "observed_monotonic_ns": snapshot.observed_monotonic_ns,
        "freshness": snapshot.freshness,
        "gate_state": snapshot.gate_state,
        "reason_codes": list(snapshot.reason_codes),
        "current": dict(snapshot.current),
        "mean_1m": dict(snapshot.mean_1m),
        "mean_10m": dict(snapshot.mean_10m),
        "peak_10m": dict(snapshot.peak_10m),
        "normalized_pressure": dict(snapshot.normalized_pressure),
        "normalized_headroom": dict(snapshot.normalized_headroom),
        "trend": dict(snapshot.trend),
        "bottleneck": snapshot.bottleneck,
        "preferred_profiles": list(snapshot.preferred_profiles),
        "avoid_profiles": list(snapshot.avoid_profiles),
        "confidence": snapshot.confidence,
        "cgroup_state": snapshot.cgroup_state,
        "thermal_state": snapshot.thermal_state,
    }


def _encode_resource_document(payload: Mapping[str, object]) -> bytes:
    try:
        raw = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        _invalid()
    if len(raw) > _RESOURCE_DOCUMENT_MAX_BYTES:
        _invalid()
    return raw


def read_resource_snapshot(
    state: HiveStateStore, *, now_utc: datetime, expected_boot_id: str
) -> ResourceSnapshotV1:
    """Read exactly one fresh snapshot from the authorized state owner."""

    store = _require_state(state)
    try:
        raw = store.read_private_bytes(_RESOURCE_SNAPSHOT_PATH, max_bytes=_RESOURCE_DOCUMENT_MAX_BYTES)
    except HiveStateError:
        _invalid()
    return parse_snapshot_document(
        _decode_resource_document(raw), now_utc=now_utc, expected_boot_id=expected_boot_id
    )


def write_resource_snapshot(state: HiveStateStore, snapshot: ResourceSnapshotV1) -> None:
    """Persist one newer snapshot without repairing corrupt prior state."""

    store = _require_state(state)
    document = _snapshot_document(snapshot)
    raw = _encode_resource_document(document)
    try:
        with store.locked():
            try:
                previous = _snapshot_from_stored_document(
                    _decode_resource_document(
                        store.read_private_bytes(_RESOURCE_SNAPSHOT_PATH, max_bytes=_RESOURCE_DOCUMENT_MAX_BYTES)
                    )
                )
            except HiveStateError as exc:
                if str(exc) != "state_not_found":
                    raise
                previous = None
            if previous is not None and previous.boot_id == snapshot.boot_id and (
                snapshot.generation <= previous.generation
                or snapshot.observed_monotonic_ns <= previous.observed_monotonic_ns
            ):
                _invalid()
            store.replace_private_bytes(_RESOURCE_SNAPSHOT_PATH, raw)
    except HiveStateError:
        _invalid()


def read_thermal_policy(state: HiveStateStore) -> ThermalPolicyV1 | None:
    """Read the independent normalized thermal policy, if one was derived."""

    store = _require_state(state)
    try:
        raw = store.read_private_bytes(_THERMAL_POLICY_PATH, max_bytes=_RESOURCE_DOCUMENT_MAX_BYTES)
    except HiveStateError as exc:
        if str(exc) == "state_not_found":
            return None
        _invalid()
    return _thermal_policy_from_document(_decode_resource_document(raw))


def write_thermal_policy(state: HiveStateStore, policy: ThermalPolicyV1) -> None:
    """Persist normalized derived thermal data as its own document."""

    store = _require_state(state)
    if not isinstance(policy, ThermalPolicyV1):
        _invalid()
    raw = _encode_resource_document(
        {
            "schema_version": policy.schema_version,
            "sensor_thresholds": dict(policy.sensor_thresholds),
        }
    )
    try:
        with store.locked():
            try:
                existing = store.read_private_bytes(_THERMAL_POLICY_PATH, max_bytes=_RESOURCE_DOCUMENT_MAX_BYTES)
            except HiveStateError as exc:
                if str(exc) != "state_not_found":
                    raise
            else:
                _thermal_policy_from_document(_decode_resource_document(existing))
            store.replace_private_bytes(_THERMAL_POLICY_PATH, raw)
    except HiveStateError:
        _invalid()


def _read_kernel_bytes(backend: ResourceInputBackend, path: Path, *, maximum: int) -> bytes:
    try:
        raw = backend.read_private_kernel_bytes(path, max_bytes=maximum)
    except Exception:
        _monitor_unavailable()
    if type(raw) is not bytes or len(raw) > maximum:
        _monitor_unavailable()
    return raw


def _strict_decimal(value: object, *, maximum: float = 100.0) -> float:
    if not isinstance(value, str) or not _DECIMAL.fullmatch(value):
        _monitor_unavailable()
    try:
        parsed = float(value)
    except ValueError:
        _monitor_unavailable()
    if not math.isfinite(parsed) or not 0 <= parsed <= maximum:
        _monitor_unavailable()
    return parsed


def _parse_loadavg(raw: bytes) -> None:
    try:
        fields = raw.decode("ascii").split()
    except UnicodeDecodeError:
        _monitor_unavailable()
    if len(fields) != 5:
        _monitor_unavailable()
    for value in fields[:3]:
        _strict_decimal(value, maximum=1_000_000.0)
    try:
        runnable, total = fields[3].split("/", 1)
        if type(int(runnable)) is not int or type(int(total)) is not int or int(total) <= 0 or int(runnable) < 0:
            _monitor_unavailable()
        if int(fields[4]) < 0:
            _monitor_unavailable()
    except ValueError:
        _monitor_unavailable()


def _parse_meminfo(raw: bytes) -> tuple[int, int]:
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError:
        _monitor_unavailable()
    parsed: dict[str, int] = {}
    for line in lines:
        fields = line.split()
        if len(fields) not in {2, 3} or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_()]*:", fields[0]):
            _monitor_unavailable()
        key = fields[0]
        if not fields[1].isdigit() or (len(fields) == 3 and fields[2] != "kB"):
            _monitor_unavailable()
        value = int(fields[1])
        if value < 0 or value > (1 << 63) - 1:
            _monitor_unavailable()
        if key in {"MemTotal:", "MemAvailable:"}:
            if key in parsed or len(fields) != 3 or fields[2] != "kB":
                _monitor_unavailable()
            parsed[key] = value
    if set(parsed) != {"MemTotal:", "MemAvailable:"} or parsed["MemAvailable:"] > parsed["MemTotal:"]:
        _monitor_unavailable()
    return parsed["MemTotal:"], parsed["MemAvailable:"]


def _parse_cpu_stat(raw: bytes) -> float:
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError:
        _monitor_unavailable()
    aggregate: list[int] | None = None
    for line in lines:
        fields = line.split()
        if not fields:
            _monitor_unavailable()
        if fields[0] == "cpu":
            if aggregate is not None or len(fields) < 6 or any(not field.isdigit() for field in fields[1:]):
                _monitor_unavailable()
            aggregate = [int(field) for field in fields[1:]]
        elif re.fullmatch(r"cpu[0-9]+", fields[0]):
            if len(fields) < 6 or any(not field.isdigit() for field in fields[1:]):
                _monitor_unavailable()
    if aggregate is None:
        _monitor_unavailable()
    values = aggregate
    if any(value > (1 << 63) - 1 for value in values):
        _monitor_unavailable()
    total = sum(values)
    if total <= 0:
        _monitor_unavailable()
    idle = values[3] + values[4]
    return (total - idle) * 100.0 / total


def _parse_psi(raw: bytes, *, require_full: bool) -> float:
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError:
        _monitor_unavailable()
    expected = {"some", "full"} if require_full else {"some"}
    parsed: dict[str, float] = {}
    for line in lines:
        fields = line.split()
        if len(fields) != 5 or fields[0] not in expected or fields[0] in parsed:
            _monitor_unavailable()
        values: dict[str, str] = {}
        for field in fields[1:]:
            key, separator, value = field.partition("=")
            if separator != "=" or key in values:
                _monitor_unavailable()
            values[key] = value
        if set(values) != {"avg10", "avg60", "avg300", "total"}:
            _monitor_unavailable()
        for key in ("avg10", "avg60", "avg300"):
            _strict_decimal(values[key])
        if not values["total"].isdigit() or int(values["total"]) > (1 << 63) - 1:
            _monitor_unavailable()
        parsed[fields[0]] = _strict_decimal(values["avg10"])
    if set(parsed) != expected:
        _monitor_unavailable()
    return parsed["some"]


def _parse_boot_id(raw: bytes) -> str:
    if len(raw) > _BOOT_ID_MAX_BYTES:
        _monitor_unavailable()
    try:
        decoded = raw.decode("ascii")
    except UnicodeDecodeError:
        _monitor_unavailable()
    if not decoded.endswith("\n") or decoded.count("\n") != 1:
        _monitor_unavailable()
    try:
        return _require_canonical_boot_id(decoded[:-1])
    except ResourceSnapshotError:
        _monitor_unavailable()


def _decode_sensor_document(raw: object) -> Mapping[str, object]:
    if type(raw) is not bytes or len(raw) > _SENSORS_STDOUT_MAX_BYTES:
        _thermal_unavailable()
    try:
        decoded = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs, parse_constant=_reject_json_constant
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError, ResourceSnapshotError):
        _thermal_unavailable()
    if not isinstance(decoded, Mapping) or len(decoded) > 256:
        _thermal_unavailable()
    return decoded


def _sensor_number(value: object) -> float:
    if type(value) not in {int, float} or not math.isfinite(value) or not 0 <= value <= 200:
        _thermal_unavailable()
    return float(value)


def resolve_thermal_policy(
    sensor_document: Mapping[str, object], *, configured_candidates: Sequence[ThermalCandidate]
) -> ThermalPolicyV1 | None:
    """Derive only normalized thresholds from one strict current sensor document."""

    if not isinstance(sensor_document, Mapping) or len(sensor_document) > 256:
        _thermal_unavailable()
    candidates = tuple(configured_candidates)
    if len(candidates) > 256 or any(not isinstance(candidate, ThermalCandidate) for candidate in candidates):
        _thermal_unavailable()
    by_id = {candidate.sensor_id: candidate for candidate in candidates}
    if len(by_id) != len(candidates):
        _thermal_unavailable()
    chips: dict[str, tuple[str, Mapping[str, object]]] = {}
    for chip, payload in sensor_document.items():
        normalized_chip = _normalize_sensor_component(chip)
        if normalized_chip in chips or not isinstance(payload, Mapping):
            _thermal_unavailable()
        adapter = payload.get("Adapter")
        if not isinstance(adapter, str):
            _thermal_unavailable()
        labels = {key: value for key, value in payload.items() if key != "Adapter"}
        if not labels or any(not isinstance(key, str) or not isinstance(value, Mapping) for key, value in labels.items()):
            _thermal_unavailable()
        chips[normalized_chip] = (_normalize_sensor_component(adapter), labels)
    known_labels = {(candidate.chip, candidate.label) for candidate in candidates}
    if set(chips) - {candidate.chip for candidate in candidates}:
        _thermal_unavailable()
    for chip, (_adapter, labels) in chips.items():
        if any((chip, _normalize_sensor_component(label)) not in known_labels for label in labels):
            _thermal_unavailable()
    thresholds: dict[str, float] = {}
    for candidate in candidates:
        chip = chips.get(candidate.chip)
        if chip is None:
            continue
        adapter, labels = chip
        if adapter != candidate.adapter:
            _thermal_unavailable()
        matching = [value for label, value in labels.items() if _normalize_sensor_component(label) == candidate.label]
        if len(matching) > 1:
            _thermal_unavailable()
        if not matching:
            continue
        reading = matching[0]
        allowed = {"temp1_input", "temp1_high", "temp1_max", "temp1_crit", "show_in_panel", "user_formula"}
        if set(reading) - allowed or "temp1_input" not in reading:
            _thermal_unavailable()
        _sensor_number(reading["temp1_input"])
        if "show_in_panel" in reading and reading["show_in_panel"] is not True:
            _thermal_unavailable()
        if "user_formula" in reading and reading["user_formula"] != "":
            _thermal_unavailable()
        if candidate.high is not None:
            threshold = candidate.high
        elif "temp1_max" in reading:
            threshold = _sensor_number(reading["temp1_max"])
        elif "temp1_crit" in reading:
            threshold = _sensor_number(reading["temp1_crit"]) * 0.9
        else:
            _thermal_unavailable()
        thresholds[candidate.sensor_id] = _require_temperature(threshold)
    if not thresholds:
        return None
    return ThermalPolicyV1(schema_version=_SCHEMA_VERSION, sensor_thresholds=thresholds)


def collect_resource_sample(
    backend: ResourceInputBackend,
    paths: ResourceInputPaths,
    *,
    clocks: ResourceClocks,
    candidates: Sequence[ThermalCandidate],
    completed_sample_count: int,
) -> ResourceSampleV1:
    """Read one complete bounded sample through injected inputs only."""

    if not isinstance(paths, ResourceInputPaths) or not isinstance(clocks, ResourceClocks):
        _invalid()
    if type(completed_sample_count) is not int or not 0 <= completed_sample_count <= _MAX_SAMPLE_BUCKETS:
        _invalid()
    _parse_loadavg(_read_kernel_bytes(backend, paths.loadavg, maximum=_KERNEL_INPUT_MAX_BYTES))
    total_kib, available_kib = _parse_meminfo(
        _read_kernel_bytes(backend, paths.meminfo, maximum=_KERNEL_INPUT_MAX_BYTES)
    )
    cpu = _parse_cpu_stat(_read_kernel_bytes(backend, paths.stat, maximum=_KERNEL_INPUT_MAX_BYTES))
    _parse_psi(_read_kernel_bytes(backend, paths.psi_cpu, maximum=_PSI_INPUT_MAX_BYTES), require_full=False)
    io = _parse_psi(_read_kernel_bytes(backend, paths.psi_io, maximum=_PSI_INPUT_MAX_BYTES), require_full=True)
    _parse_psi(_read_kernel_bytes(backend, paths.psi_memory, maximum=_PSI_INPUT_MAX_BYTES), require_full=True)
    boot_id = _parse_boot_id(_read_kernel_bytes(backend, paths.boot_id, maximum=_BOOT_ID_MAX_BYTES))
    memory = (total_kib - available_kib) * 100.0 / total_kib
    try:
        sensor_raw = backend.run_sensors_json(
            argv=("/usr/bin/sensors", "-j"),
            environment={"LC_ALL": "C", "LANG": "C", "PATH": "/usr/bin:/bin"},
            stdin_closed=True,
            timeout_seconds=_SENSORS_TIMEOUT_SECONDS,
            max_stdout_bytes=_SENSORS_STDOUT_MAX_BYTES,
            max_stderr_bytes=_SENSORS_STDERR_MAX_BYTES,
        )
    except Exception:
        thermal_state: Literal["warming_up", "no_valid_sensors", "ready", "monitor_unavailable"] = "monitor_unavailable"
        policy = None
    else:
        policy = resolve_thermal_policy(_decode_sensor_document(sensor_raw), configured_candidates=candidates)
        if completed_sample_count < _MIN_COMPLETE_SAMPLES:
            thermal_state = "warming_up"
        else:
            thermal_state = "ready" if policy is not None else "no_valid_sensors"
    try:
        observed_at_utc = _require_utc_datetime(clocks.now_utc())
        observed_monotonic_ns = _require_positive_int(clocks.monotonic_ns())
    except (ResourceSnapshotError, Exception):
        _monitor_unavailable()
    return ResourceSampleV1(
        boot_id=boot_id,
        observed_at_utc=observed_at_utc,
        observed_monotonic_ns=observed_monotonic_ns,
        current={"cpu": cpu, "io": io, "memory": memory},
        cgroup_state="unavailable",
        thermal_state=thermal_state,
        thermal_policy=policy,
    )


def _mean(samples: Sequence[ResourceSampleV1], dimension: str) -> float:
    return sum(sample.current[dimension] for sample in samples) / len(samples)


def build_monitor_snapshot(
    samples: Sequence[ResourceSampleV1], *, prior_generation: int, clocks: ResourceClocks
) -> ResourceSnapshotV1:
    """Build one generation only from a complete, bounded one-Hz sample window."""

    if not isinstance(clocks, ResourceClocks) or type(prior_generation) is not int or prior_generation < 0:
        _invalid()
    samples = tuple(samples)
    if len(samples) < _MIN_COMPLETE_SAMPLES:
        _thermal_unavailable()
    if len(samples) > _MAX_SAMPLE_BUCKETS or any(not isinstance(sample, ResourceSampleV1) for sample in samples):
        _invalid()
    first = samples[0]
    for previous, current in zip(samples, samples[1:]):
        if (
            current.boot_id != first.boot_id
            or current.observed_monotonic_ns - previous.observed_monotonic_ns != _ONE_SECOND_NS
            or current.observed_at_utc - previous.observed_at_utc != timedelta(seconds=1)
        ):
            _invalid()
    latest = samples[-1]
    try:
        now_utc = _require_utc_datetime(clocks.now_utc())
        now_monotonic_ns = _require_positive_int(clocks.monotonic_ns())
    except (ResourceSnapshotError, Exception):
        _monitor_unavailable()
    if (
        latest.observed_at_utc > now_utc
        or now_utc - latest.observed_at_utc > _FRESHNESS_MAX_AGE
        or now_monotonic_ns < latest.observed_monotonic_ns
    ):
        _monitor_unavailable()
    means = {dimension: _mean(samples, dimension) for dimension in _DIMENSIONS}
    peaks = {dimension: max(sample.current[dimension] for sample in samples) for dimension in _DIMENSIONS}
    assessments = {dimension: classify_trend([round(sample.current[dimension]) for sample in samples]) for dimension in _DIMENSIONS}
    confidence: Literal["high", "low"] = "high" if all(
        assessment.confidence == "high" for assessment in assessments.values()
    ) else "low"
    trend = {
        dimension: assessments[dimension].trend if confidence == "high" else None for dimension in _DIMENSIONS
    }
    pressure = {dimension: int(round(latest.current[dimension])) for dimension in _DIMENSIONS}
    headroom = {dimension: 100 - pressure[dimension] for dimension in _DIMENSIONS}
    reasons: tuple[str, ...] = ("resource_ready",)
    gate_state: Literal["ready", "blocked"] = "ready"
    bottleneck: Literal["cpu", "io", "memory", "thermal", "cgroup", "unknown"] = "unknown"
    if latest.thermal_state in {"warming_up", "monitor_unavailable"}:
        reasons = ("temperature_monitor_unavailable",)
        gate_state = "blocked"
        bottleneck = "thermal"
    elif latest.cgroup_state != "ready":
        reasons = ("cgroup_preflight_failed",)
        gate_state = "blocked"
        bottleneck = "cgroup"
    return ResourceSnapshotV1(
        schema_version=_SCHEMA_VERSION,
        boot_id=latest.boot_id,
        generation=prior_generation + 1,
        observed_at_utc=latest.observed_at_utc,
        observed_monotonic_ns=latest.observed_monotonic_ns,
        freshness="fresh",
        gate_state=gate_state,
        reason_codes=reasons,
        current=latest.current,
        mean_1m=means,
        mean_10m=means,
        peak_10m=peaks,
        normalized_pressure=pressure,
        normalized_headroom=headroom,
        trend=trend,
        bottleneck=bottleneck,
        preferred_profiles=("balanced",),
        avoid_profiles=(),
        confidence=confidence,
        cgroup_state=latest.cgroup_state,
        thermal_state=latest.thermal_state,
    )


def build_resource_gate_facts(snapshot: ResourceSnapshotV1) -> ResourceGateFacts:
    return ResourceGateFacts(
        generation=snapshot.generation,
        observed_at_utc=snapshot.observed_at_utc,
        observed_monotonic_ns=snapshot.observed_monotonic_ns,
        gate_state=snapshot.gate_state,
        reason_codes=snapshot.reason_codes,
        current=snapshot.current,
        normalized_pressure=snapshot.normalized_pressure,
        normalized_headroom=snapshot.normalized_headroom,
        bottleneck=snapshot.bottleneck,
        cgroup_state=snapshot.cgroup_state,
        thermal_state=snapshot.thermal_state,
    )


def build_resource_operator_status(snapshot: ResourceSnapshotV1) -> ResourceOperatorStatus:
    return ResourceOperatorStatus(
        schema_version=snapshot.schema_version,
        generation=snapshot.generation,
        state=snapshot.gate_state,
        bottleneck=snapshot.bottleneck,
        current=snapshot.current,
        mean_1m=snapshot.mean_1m,
        mean_10m=snapshot.mean_10m,
        peak_10m=snapshot.peak_10m,
        trend=snapshot.trend if snapshot.confidence == "high" else {},
        confidence=snapshot.confidence,
        preferred_profiles=snapshot.preferred_profiles,
        avoid_profiles=snapshot.avoid_profiles,
        reason_codes=snapshot.reason_codes,
    )


def build_resource_scheduler_snapshot(snapshot: ResourceSnapshotV1) -> ResourceSchedulerSnapshot:
    return ResourceSchedulerSnapshot(
        schema_version=snapshot.schema_version,
        generation=snapshot.generation,
        confidence=snapshot.confidence,
        normalized_pressure=snapshot.normalized_pressure,
        preferred_profiles=snapshot.preferred_profiles,
        avoid_profiles=snapshot.avoid_profiles,
    )


def classify_trend(buckets: Sequence[int]) -> TrendAssessmentV1:
    """Classify bounded percentage buckets without guessing at low confidence."""

    if any(type(value) is not int or not 0 <= value <= 100 for value in buckets):
        raise ResourceSnapshotError("resource_snapshot_invalid")
    if len(buckets) < 10:
        return TrendAssessmentV1(trend=None, confidence="low")
    previous = sum(buckets[-10:-2]) / 8
    recent = sum(buckets[-2:]) / 2
    if recent - previous >= 5:
        return TrendAssessmentV1(trend="rising", confidence="high")
    if recent - previous <= -5:
        return TrendAssessmentV1(trend="falling", confidence="high")
    return TrendAssessmentV1(trend="stable", confidence="high")
