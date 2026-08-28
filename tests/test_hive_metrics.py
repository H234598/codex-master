from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from codex_master.fleet_overview import FleetOverviewAgentRow, FleetOverviewSeriesRow, FleetOverviewSnapshot
from codex_master.hive_metrics import HiveMetricsError, fleet_metric_values, pcp_htop_meter_config, render_openmetrics


NOW = datetime(2026, 8, 21, 12, 0, tzinfo=timezone.utc)


def agent(agent_id: str, provider: str, role: str | None) -> FleetOverviewAgentRow:
    return FleetOverviewAgentRow(
        agent_id, "runtime", provider, "headless", "model", None, None, "running", role, None,
        None, None, None, None, None, "unavailable",
    )


def overview(
    *,
    agents: tuple[FleetOverviewAgentRow, ...] | None = None,
    created_at: datetime = NOW,
    registered_homes: int | None = None,
) -> FleetOverviewSnapshot:
    active_agents = agents if agents is not None else (
        agent("oa-queen", "openai_chatgpt", "koenigin"),
        agent("oa-worker", "openai_api", "arbeitsbiene"),
        agent("g-worker", "gemini_api", "exploriererin"),
        agent("an-tl", "anthropic_api", "teamleiterin"),
        agent("hu-worker", "huggingface_inference", "worker"),
        agent("ol-worker", "ollama_local", "worker"),
        agent("ds-goddess", "deepseek_api", "gottbiene"),
        agent("rogue", "openai_api", "rogue"),
    )
    home_count = len(active_agents) if registered_homes is None else registered_homes
    registered_ids = tuple(row.agent_id for row in active_agents) + tuple(
        f"stopped-{index}" for index in range(home_count - len(active_agents))
    )
    return FleetOverviewSnapshot(
        7, created_at, "fresh",
        (
            FleetOverviewSeriesRow(
                "h", "Hive", "openai_api", "codex_cli", "model", len(active_agents), home_count,
                registered_ids,
            ),
        ), active_agents, (), (),
    )


def test_fleet_metrics_count_active_observations_and_registered_homes_separately() -> None:
    values = fleet_metric_values(overview(registered_homes=13), native_active=3, observed_at=NOW)
    assert values["codex_master_bees_native"] == 3
    assert values["codex_master_bees_codex"] == 3
    assert values["codex_master_bees_gemini"] == 1
    assert values["codex_master_bees_claude"] == 1
    assert values["codex_master_bees_huggingface"] == 1
    assert values["codex_master_bees_ollama"] == 1
    assert values["codex_master_bees_deepseek"] == 1
    assert values["codex_master_bees_goddess"] == 1
    assert values["codex_master_bees_queen"] == 1
    assert values["codex_master_bees_teamleader"] == 1
    assert values["codex_master_bees_worker"] == 4
    assert values["codex_master_bees_rogue"] == 1
    assert values["codex_master_bees_total"] == 11
    assert values["codex_master_homes_registered"] == 13


def test_fleet_metrics_expose_unknown_provider_and_role_counts() -> None:
    values = fleet_metric_values(
        overview(agents=overview().agents + (
            agent("unknown-provider", "mistral", "architect"),
            agent("unknown-role", "openai_api", None),
        )),
        native_active=0,
        observed_at=NOW,
    )
    assert values["codex_master_bees_total"] == 10
    assert values["codex_master_bees_provider_unknown"] == 1
    assert values["codex_master_bees_role_unknown"] == 2


def test_stale_snapshot_keeps_last_valid_values_at_exact_60_second_boundary() -> None:
    snapshot = overview()
    at_boundary = fleet_metric_values(snapshot, native_active=3, observed_at=NOW + timedelta(seconds=60))
    stale = fleet_metric_values(snapshot, native_active=3, observed_at=NOW + timedelta(seconds=60, microseconds=1))
    assert at_boundary["codex_master_snapshot_stale"] == 0
    assert stale["codex_master_snapshot_stale"] == 1
    assert stale["codex_master_snapshot_age_seconds"] == 60.000001
    assert stale["codex_master_snapshot_observed_at_seconds"] == NOW.timestamp()
    assert stale["codex_master_bees_total"] == 11
    assert stale["codex_master_bees_codex"] == 3


def test_invalid_observation_is_not_masked_as_stale() -> None:
    invalid_snapshot = replace(overview(), agents=(replace(overview().agents[0], provider=None),))
    with pytest.raises(HiveMetricsError, match="invalid_hive_metrics_input"):
        fleet_metric_values(
            invalid_snapshot,
            native_active=0,
            observed_at=NOW + timedelta(seconds=61),
        )


def test_invalid_snapshot_schema_remains_a_metrics_error() -> None:
    invalid_snapshot = replace(overview(), created_at=None)
    with pytest.raises(HiveMetricsError, match="invalid_hive_metrics_input"):
        fleet_metric_values(invalid_snapshot, native_active=0, observed_at=NOW)


def test_openmetrics_and_pcp_names_are_stable() -> None:
    rendered = render_openmetrics(fleet_metric_values(overview(), native_active=3, observed_at=NOW))
    assert "# TYPE codex_master_bees_native gauge" in rendered
    assert rendered.endswith("# EOF\n")
    meters = pcp_htop_meter_config()
    assert "[codex_master_provider_bees]" in meters
    assert "native.metric = openmetrics.codexmaster.codex_master_bees_native" in meters
    assert "ollama.metric = openmetrics.codexmaster.codex_master_bees_ollama" in meters
    assert "deepseek.metric = openmetrics.codexmaster.codex_master_bees_deepseek" in meters
    assert "unknown.metric = openmetrics.codexmaster.codex_master_bees_provider_unknown" in meters
    assert "[codex_master_role_bees]" in meters
    assert "unknown.metric = openmetrics.codexmaster.codex_master_bees_role_unknown" in meters
