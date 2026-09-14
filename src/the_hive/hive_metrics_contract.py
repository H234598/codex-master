from __future__ import annotations

import math
from collections.abc import Mapping
from datetime import datetime

from .fleet_overview import FleetOverviewAgentRow, FleetOverviewSeriesRow, FleetOverviewSnapshot


class HiveMetricsError(ValueError):
    pass


_PROVIDER_METRIC = {
    "openai": "codex", "openai_api": "codex", "openai_chatgpt": "codex", "codex_cli": "codex",
    "gemini": "gemini", "gemini_api": "gemini", "gemini_cli": "gemini", "google": "gemini",
    "anthropic": "claude", "anthropic_api": "claude", "claude": "claude",
    "huggingface": "huggingface", "huggingface_inference": "huggingface", "hf": "huggingface",
    "ollama": "ollama", "ollama_local": "ollama", "deepseek": "deepseek", "deepseek_api": "deepseek",
}
_ROLE_METRIC = {
    "goddess": "goddess", "gottbiene": "goddess", "gottesbiene": "goddess",
    "koenigin": "queen", "königin": "queen", "queen": "queen",
    "teamlead": "teamleader", "teamleader": "teamleader", "teamleiterin": "teamleader",
    "arbeitsbiene": "worker", "explorer": "worker", "exploriererin": "worker", "worker": "worker",
    "rogue": "rogue", "rouge": "rogue",
}
_PROVIDER_KEYS = ("codex", "gemini", "claude", "huggingface", "ollama", "deepseek")
_ROLE_KEYS = ("goddess", "queen", "teamleader", "worker", "rogue")
_STALE_AFTER_SECONDS = 60


def _invalid() -> None:
    raise HiveMetricsError("invalid_hive_metrics_input")


def _valid_token(value: object) -> bool:
    return type(value) is str and bool(value) and len(value) <= 128


def _registered_homes(overview: FleetOverviewSnapshot) -> int:
    homes = 0
    for row in overview.series:
        if (
            type(row) is not FleetOverviewSeriesRow
            or type(row.active_count) is not int
            or type(row.total_count) is not int
            or not 0 <= row.active_count <= row.total_count
            or type(row.agent_ids) is not tuple
            or len(row.agent_ids) != row.total_count
        ):
            _invalid()
        homes += row.total_count
    if homes > 100_000:
        _invalid()
    return homes


def fleet_metric_values(
    overview: FleetOverviewSnapshot, *, native_active: int, observed_at: datetime,
) -> dict[str, int | float]:
    if (
        type(overview) is not FleetOverviewSnapshot or type(native_active) is not int
        or native_active < 0 or native_active > 100_000
        or type(overview.generation) is not int
        or not isinstance(observed_at, datetime) or observed_at.tzinfo is None
        or not isinstance(overview.created_at, datetime) or overview.created_at.tzinfo is None
        or type(overview.agents) is not tuple or type(overview.series) is not tuple
        or any(
            type(row) is not FleetOverviewAgentRow
            or not _valid_token(row.provider)
            or (row.principal_role is not None and not _valid_token(row.principal_role))
            for row in overview.agents
        )
    ):
        _invalid()
    try:
        age = (observed_at - overview.created_at).total_seconds()
        measured_at = overview.created_at.timestamp()
    except (OverflowError, TypeError, ValueError):
        _invalid()
    if not math.isfinite(age) or age < 0 or not math.isfinite(measured_at):
        _invalid()
    registered_homes = _registered_homes(overview)
    values: dict[str, int | float] = {
        "codex_master_bees_native": native_active,
        "codex_master_bees_total": len(overview.agents) + native_active,
        "codex_master_homes_registered": registered_homes,
        "codex_master_fleet_generation": overview.generation,
        "codex_master_snapshot_age_seconds": age,
        "codex_master_snapshot_observed_at_seconds": measured_at,
        "codex_master_snapshot_stale": int(age > _STALE_AFTER_SECONDS),
    }
    values.update({f"codex_master_bees_{key}": 0 for key in _PROVIDER_KEYS})
    values.update({f"codex_master_bees_{key}": 0 for key in _ROLE_KEYS})
    values["codex_master_bees_provider_unknown"] = 0
    values["codex_master_bees_role_unknown"] = 0
    for row in overview.agents:
        provider_key = _PROVIDER_METRIC.get(row.provider.lower())
        if provider_key is not None:
            values[f"codex_master_bees_{provider_key}"] += 1
        else:
            values["codex_master_bees_provider_unknown"] += 1
        role_key = _ROLE_METRIC.get(row.principal_role.lower()) if row.principal_role is not None else None
        if role_key is not None:
            values[f"codex_master_bees_{role_key}"] += 1
        else:
            values["codex_master_bees_role_unknown"] += 1
    return values


def render_openmetrics(values: Mapping[str, int | float]) -> str:
    if not isinstance(values, Mapping) or not values or len(values) > 128:
        _invalid()
    lines: list[str] = []
    for name in sorted(values):
        value = values[name]
        if (
            not isinstance(name, str) or not name.startswith("codex_master_")
            or not name.replace("_", "").isalnum() or isinstance(value, bool)
            or not isinstance(value, (int, float)) or not math.isfinite(value)
        ):
            _invalid()
        rendered = str(value) if isinstance(value, int) else format(value, ".6g")
        lines.extend((f"# TYPE {name} gauge", f"{name} {rendered}"))
    return "\n".join((*lines, "# EOF", ""))


def pcp_htop_meter_config() -> str:
    return """[codex_master_provider_bees]
caption = Bienen Provider
type = text
native.metric = openmetrics.codexmaster.codex_master_bees_native
native.label = Native Bienen
native.color = green
codex.metric = openmetrics.codexmaster.codex_master_bees_codex
codex.label = Codex Bienen
codex.color = green
gemini.metric = openmetrics.codexmaster.codex_master_bees_gemini
gemini.label = Gemini Bienen
gemini.color = green
claude.metric = openmetrics.codexmaster.codex_master_bees_claude
claude.label = Claude Bienen
claude.color = green
huggingface.metric = openmetrics.codexmaster.codex_master_bees_huggingface
huggingface.label = HF Bienen
huggingface.color = green
ollama.metric = openmetrics.codexmaster.codex_master_bees_ollama
ollama.label = Ollama Bienen
ollama.color = green
deepseek.metric = openmetrics.codexmaster.codex_master_bees_deepseek
deepseek.label = DeepSeek Bienen
deepseek.color = green
unknown.metric = openmetrics.codexmaster.codex_master_bees_provider_unknown
unknown.label = Unbekannte Provider
unknown.color = red

[codex_master_role_bees]
caption = Bienen Klassen
type = text
goddess.metric = openmetrics.codexmaster.codex_master_bees_goddess
goddess.label = Gottbienen
goddess.color = green
queen.metric = openmetrics.codexmaster.codex_master_bees_queen
queen.label = Königinnen
queen.color = green
teamleader.metric = openmetrics.codexmaster.codex_master_bees_teamleader
teamleader.label = Teamleiterinnen
teamleader.color = green
worker.metric = openmetrics.codexmaster.codex_master_bees_worker
worker.label = Arbeiterinnen
worker.color = green
rogue.metric = openmetrics.codexmaster.codex_master_bees_rogue
rogue.label = Rogue
rogue.color = red
unknown.metric = openmetrics.codexmaster.codex_master_bees_role_unknown
unknown.label = Unbekannte Rollen
unknown.color = red
"""
