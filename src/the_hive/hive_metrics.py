from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from itertools import islice

from .fleet_overview import FleetOverviewSnapshot


_PROVIDER_BUCKETS = (
    "native",
    "codex",
    "gemini",
    "claude",
    "hf",
    "ollama",
    "deepseek",
    "unknown",
)
_ROLE_BUCKETS = ("godbee", "queen", "team_lead", "worker", "rogue", "unknown")
_TOKEN_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
_MODEL_TIER_RE = re.compile(r"^M[0-9]$")
_REASONING_TIER_RE = re.compile(r"^R[0-9]$")
_OBSERVATION_KEY_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_OBSERVATIONS = 4096
_MAX_DETAILS = 128
_MAX_BLOCK_DEVICES = 64
_UNKNOWN_SPECIAL_CLASS = "unknown"
_HEALTH_STATES = ("OK", "WARN", "BLOCK", "CONTAMINATED", "STALE", "RUCKEL-HOLD")
_DEVICE_RE = re.compile(r"^(?:mmcblk[0-9]+|nvme[0-9]+n[0-9]+|sd[a-z]+)$")
_TRANSPORTS = frozenset({"ata", "nvme", "scsi", "usb"})


class HiveMetricsError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class FleetMetricObservation:
    active: bool
    valid: bool
    provider: str
    role: str
    special_class: str | None = None
    model_tier: str | None = None
    reasoning_tier: str | None = None
    lifecycle: str | None = None
    observation_key: str | None = field(default=None, repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class FleetMetricBlockDevice:
    device: str
    read_per_second: float
    write_per_second: float
    in_flight: int
    busy_percent: float
    weighted_queue_seconds: float
    transport: str
    physical: bool


@dataclass(frozen=True, slots=True)
class FleetMetricIoPsi:
    some_avg10: float
    full_avg10: float
    full_avg60: float


@dataclass(frozen=True, slots=True)
class FleetMetricSnapshot:
    observations: tuple[FleetMetricObservation, ...]
    registered_homes: int
    captured_at: datetime
    block_devices: tuple[FleetMetricBlockDevice, ...] = ()
    hive_io_psi: FleetMetricIoPsi | None = None
    health_state: str = "OK"

    def __post_init__(self) -> None:
        if type(self.observations) is not tuple or type(self.block_devices) is not tuple:
            raise HiveMetricsError("invalid_metric_input")


@dataclass(frozen=True, slots=True)
class FleetMetricDetail:
    provider: str
    role: str
    special_class: str
    model_tier: str
    reasoning_tier: str
    lifecycle: str


@dataclass(frozen=True, slots=True)
class FleetMetricProjection:
    state: str
    age_seconds: float | None
    registered_homes: int
    active_bees: int | None
    provider_counts: tuple[tuple[str, int], ...] | None
    role_counts: tuple[tuple[str, int], ...] | None
    details: tuple[FleetMetricDetail, ...]
    details_truncated: bool
    block_devices: tuple[FleetMetricBlockDevice, ...] = ()
    hive_io_psi: FleetMetricIoPsi | None = None
    health_state: str = "OK"


def _token(value: object) -> str | None:
    if type(value) is not str or _TOKEN_RE.fullmatch(value) is None:
        return None
    return value


def _observation_key(value: object) -> str | None:
    if type(value) is not str or _OBSERVATION_KEY_RE.fullmatch(value) is None:
        return None
    return value


def _opaque_observation_key(generation: int, source: str, value: str) -> str:
    payload = f"{generation}:{source}:{value}".encode("ascii")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _provider_bucket(value: str) -> str:
    aliases = {
        "native": "native",
        "codex": "codex",
        "openai": "codex",
        "openai_api": "codex",
        "openai_chatgpt": "codex",
        "codex_cli": "codex",
        "gemini": "gemini",
        "gemini_api": "gemini",
        "claude": "claude",
        "claude_api": "claude",
        "anthropic": "claude",
        "hf": "hf",
        "hf_inference": "hf",
        "huggingface": "hf",
        "huggingface_inference": "hf",
        "ollama": "ollama",
        "ollama_local": "ollama",
        "deepseek": "deepseek",
    }
    return aliases.get(value.lower(), "unknown")


def _role_bucket(value: str) -> str:
    aliases = {
        "godbee": "godbee",
        "goddess": "godbee",
        "gottbiene": "godbee",
        "goettin": "godbee",
        "queen": "queen",
        "koenigin": "queen",
        "team_lead": "team_lead",
        "tl": "team_lead",
        "teamlead": "team_lead",
        "teamleiterin": "team_lead",
        "worker": "worker",
        "arbeitsbiene": "worker",
        "rogue": "rogue",
    }
    return aliases.get(value.lower(), "unknown")


def _projection_invalid(registered_homes: int) -> FleetMetricProjection:
    return FleetMetricProjection(
        "invalid", None, registered_homes, None, None, None, (), False, (), None, "CONTAMINATED"
    )


def _project_block_device(value: object) -> FleetMetricBlockDevice | None:
    if type(value) is not FleetMetricBlockDevice:
        return None
    if (
        type(value.physical) is not bool
        or not value.physical
        or type(value.device) is not str
        or _DEVICE_RE.fullmatch(value.device) is None
        or type(value.transport) is not str
        or value.transport not in _TRANSPORTS
        or type(value.in_flight) is not int
        or not 0 <= value.in_flight <= _MAX_OBSERVATIONS
        or type(value.busy_percent) not in (int, float)
        or not math.isfinite(value.busy_percent)
        or not 0 <= value.busy_percent <= 100
        or type(value.read_per_second) not in (int, float)
        or not math.isfinite(value.read_per_second)
        or value.read_per_second < 0
        or type(value.write_per_second) not in (int, float)
        or not math.isfinite(value.write_per_second)
        or value.write_per_second < 0
        or type(value.weighted_queue_seconds) not in (int, float)
        or not math.isfinite(value.weighted_queue_seconds)
        or value.weighted_queue_seconds < 0
    ):
        return None
    return FleetMetricBlockDevice(
        value.device,
        float(value.read_per_second),
        float(value.write_per_second),
        value.in_flight,
        float(value.busy_percent),
        float(value.weighted_queue_seconds),
        value.transport,
        True,
    )


def _project_io_psi(value: object) -> FleetMetricIoPsi | None:
    if type(value) is not FleetMetricIoPsi:
        return None
    if any(
        type(item) not in (int, float)
        or not math.isfinite(item)
        or not 0 <= item <= 100
        for item in (value.some_avg10, value.full_avg10, value.full_avg60)
    ):
        return None
    return value


def project_hive_metrics(
    *,
    observations: Iterable[FleetMetricObservation] | None = None,
    registered_homes: int | None = None,
    captured_at: datetime | None = None,
    observed_at: datetime,
    stale_after_seconds: int = 60,
    snapshot: FleetMetricSnapshot | None = None,
) -> FleetMetricProjection:
    if snapshot is not None:
        if observations is not None or registered_homes is not None or captured_at is not None:
            raise HiveMetricsError("invalid_metric_input")
        if type(snapshot) is not FleetMetricSnapshot:
            raise HiveMetricsError("invalid_metric_input")
        observations = snapshot.observations
        registered_homes = snapshot.registered_homes
        captured_at = snapshot.captured_at
        health_state = snapshot.health_state
    else:
        block_devices = ()
        hive_io_psi = None
        health_state = "OK"
    if (
        type(registered_homes) is not int
        or not 0 <= registered_homes <= _MAX_OBSERVATIONS
        or type(stale_after_seconds) is not int
        or not 1 <= stale_after_seconds <= 86400
        or not isinstance(captured_at, datetime)
        or not isinstance(observed_at, datetime)
        or captured_at.tzinfo is None
        or observed_at.tzinfo is None
        or type(health_state) is not str
        or health_state not in _HEALTH_STATES
    ):
        raise HiveMetricsError("invalid_metric_input")
    if snapshot is not None:
        if len(snapshot.block_devices) > _MAX_BLOCK_DEVICES:
            return _projection_invalid(registered_homes)
        block_devices = tuple(
            projected
            for device in snapshot.block_devices
            if (projected := _project_block_device(device)) is not None
        )
        if len(block_devices) != len(snapshot.block_devices):
            return _projection_invalid(registered_homes)
        hive_io_psi = _project_io_psi(snapshot.hive_io_psi) if snapshot.hive_io_psi is not None else None
        if snapshot.hive_io_psi is not None and hive_io_psi is None:
            return _projection_invalid(registered_homes)
    try:
        items = tuple(islice(iter(observations), _MAX_OBSERVATIONS + 1))
        age_seconds = (observed_at - captured_at).total_seconds()
    except Exception:
        raise HiveMetricsError("invalid_metric_input") from None
    if len(items) > _MAX_OBSERVATIONS or not math.isfinite(age_seconds) or age_seconds < 0:
        raise HiveMetricsError("invalid_metric_input")

    providers = {bucket: 0 for bucket in _PROVIDER_BUCKETS}
    roles = {bucket: 0 for bucket in _ROLE_BUCKETS}
    details: list[FleetMetricDetail] = []
    keyed_observations: dict[str, FleetMetricObservation] = {}
    for observation in items:
        if type(observation) is not FleetMetricObservation:
            return _projection_invalid(registered_homes)
        observation_key = observation.observation_key
        if observation_key is not None and _observation_key(observation_key) is None:
            return _projection_invalid(registered_homes)
        provider = _token(observation.provider)
        role = _token(observation.role)
        if type(observation.active) is not bool or type(observation.valid) is not bool:
            return _projection_invalid(registered_homes)
        detail_values = (
            observation.special_class,
            observation.model_tier,
            observation.reasoning_tier,
            observation.lifecycle,
        )
        if provider is None or role is None or not observation.valid:
            return _projection_invalid(registered_homes)
        if any(value is None for value in detail_values) and any(
            value is not None for value in detail_values
        ):
            return _projection_invalid(registered_homes)
        if observation_key is not None:
            previous = keyed_observations.get(observation_key)
            if previous is not None:
                if previous != observation:
                    return _projection_invalid(registered_homes)
                continue
            keyed_observations[observation_key] = observation
        if not observation.active:
            continue
        provider_bucket = _provider_bucket(provider)
        role_bucket = _role_bucket(role)
        providers[provider_bucket] += 1
        roles[role_bucket] += 1
        if all(value is not None for value in detail_values):
            _special_class, model_tier, reasoning_tier, lifecycle = detail_values
            if (
                type(model_tier) is not str
                or _MODEL_TIER_RE.fullmatch(model_tier) is None
                or type(reasoning_tier) is not str
                or _REASONING_TIER_RE.fullmatch(reasoning_tier) is None
                or lifecycle not in {"ephemeral", "invocation", "binding", "persistent"}
            ):
                return _projection_invalid(registered_homes)
            details.append(
                FleetMetricDetail(
                    provider_bucket,
                    role_bucket,
                    _UNKNOWN_SPECIAL_CLASS,
                    model_tier,
                    reasoning_tier,
                    lifecycle,
                )
            )
    ordered_details = tuple(sorted(details, key=lambda item: (
        item.provider,
        item.role,
        item.special_class,
        item.model_tier,
        item.reasoning_tier,
        item.lifecycle,
    )))
    return FleetMetricProjection(
        "stale" if health_state == "STALE" or age_seconds > stale_after_seconds else "fresh",
        float(age_seconds),
        registered_homes,
        sum(providers.values()),
        tuple(providers.items()),
        tuple(roles.items()),
        ordered_details[:_MAX_DETAILS],
        len(ordered_details) > _MAX_DETAILS,
        block_devices,
        hive_io_psi,
        "STALE" if health_state == "STALE" or age_seconds > stale_after_seconds else health_state,
    )


def pcp_htop_meter_config() -> tuple[str, str]:
    return (
        "[textmeter provider_runtime]\n"
        "metrics = codex_master_bees_native,codex_master_bees_codex,"
        "codex_master_bees_gemini,codex_master_bees_claude,"
        "codex_master_bees_hf,codex_master_bees_ollama,"
        "codex_master_bees_deepseek,codex_master_bees_unknown\n"
        "labels = Native,Codex/OpenAI,Gemini,Claude,HF,Ollama,DeepSeek,unknown\n",
        "[textmeter hierarchy]\n"
        "metrics = codex_master_roles_godbee,codex_master_roles_queen,"
        "codex_master_roles_team_lead,codex_master_roles_worker,"
        "codex_master_roles_rogue,codex_master_roles_unknown\n"
        "labels = Gottbiene,Königin,TL,Arbeiterin,Rogue,unknown\n",
    )


def _metric_values_from_projection(
    projection: FleetMetricProjection,
) -> dict[str, int | float]:
    if projection.state == "invalid" or projection.active_bees is None:
        raise HiveMetricsError("invalid_metric_input")
    values: dict[str, int | float] = {
        "codex_master_bees_total": projection.active_bees,
        "codex_master_homes_registered": projection.registered_homes,
        "codex_master_hive_metrics_stale": int(projection.state == "stale"),
        "codex_master_hive_metrics_invalid": 0,
        "codex_master_hive_metrics_age_seconds": projection.age_seconds or 0.0,
    }
    for bucket, value in projection.provider_counts or ():
        values[f"codex_master_bees_{bucket}"] = value
    for bucket, value in projection.role_counts or ():
        values[f"codex_master_roles_{bucket}"] = value
    return values


def fleet_metric_values(
    overview: FleetOverviewSnapshot | FleetMetricSnapshot,
    *,
    native_active: int | None = None,
    native_generation: int | None = None,
    observed_at: datetime,
) -> dict[str, int | float]:
    if type(overview) is FleetMetricSnapshot:
        if native_active is not None or native_generation is not None:
            raise HiveMetricsError("invalid_metric_input")
        return _metric_values_from_projection(
            project_hive_metrics(snapshot=overview, observed_at=observed_at)
        )
    if (
        type(overview) is not FleetOverviewSnapshot
        or type(overview.generation) is not int
        or overview.generation < 0
        or type(native_active) is not int
        or not 0 <= native_active <= _MAX_OBSERVATIONS
        or (
            native_generation is not None
            and (
                type(native_generation) is not int
                or native_generation != overview.generation
            )
        )
        or (native_active > 0 and native_generation != overview.generation)
    ):
        raise HiveMetricsError("invalid_metric_input")
    observations: list[FleetMetricObservation] = []
    registered_homes = 0
    try:
        for series in overview.series:
            if type(series.total_count) is not int or series.total_count < 0:
                raise ValueError
            registered_homes += series.total_count
        for row in overview.agents:
            if row.state != "running":
                continue
            agent_id = _token(row.agent_id)
            if agent_id is None:
                raise ValueError
            observations.append(
                FleetMetricObservation(
                    True,
                    True,
                    row.provider,
                    row.principal_role or "unknown",
                    observation_key=_opaque_observation_key(
                        overview.generation, "overview", agent_id
                    ),
                )
            )
        observations.extend(
            FleetMetricObservation(
                True,
                True,
                "native",
                "unknown",
                observation_key=_opaque_observation_key(
                    overview.generation, "native", str(ordinal)
                ),
            )
            for ordinal in range(native_active)
        )
    except Exception:
        raise HiveMetricsError("invalid_metric_input") from None
    projection = project_hive_metrics(
        observations=observations,
        registered_homes=registered_homes,
        captured_at=overview.created_at,
        observed_at=observed_at,
    )
    return _metric_values_from_projection(projection)


def render_openmetrics(values: Mapping[str, int | float]) -> str:
    if not isinstance(values, Mapping) or len(values) > 64:
        raise HiveMetricsError("invalid_metric_values")
    rendered: list[str] = []
    for name, value in sorted(values.items()):
        if (
            type(name) is not str
            or re.fullmatch(r"[a-z][a-z0-9_]{0,127}", name) is None
            or type(value) not in (int, float)
            or not math.isfinite(value)
            or value < 0
        ):
            raise HiveMetricsError("invalid_metric_values")
        rendered.append(f"{name} {format(value, '.15g')}\n")
    rendered.append("# EOF\n")
    return "".join(rendered)
