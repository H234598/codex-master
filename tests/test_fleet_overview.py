from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_master.fleet_overview import (
    FleetOverviewAgentContext,
    FleetOverviewAccountLimitRow,
    FleetOverviewAgentRow,
    FleetOverviewError,
    FleetOverviewSeriesRow,
    FleetOverviewSnapshot,
    build_fleet_overview,
    enrich_fleet_overview_usage,
    fleet_overview_document,
    render_fleet_overview,
)
from codex_master.fleet_registry import (
    AuthKind,
    FleetAccount,
    FleetAccountV2,
    FleetSeries,
    FleetSeriesMember,
    FleetSeriesV2,
    FleetSnapshot,
    FleetSnapshotV2,
    LimitState,
    Provider,
    RunnerKind,
    SecretState,
    build_inventory,
)
from codex_master.usage_snapshot import (
    AccountUsage,
    UsageCostWindow,
    UsageLimit,
    UsageSnapshot,
)


CREATED = datetime(2026, 8, 15, 12, 0, tzinfo=timezone.utc)
POOL = Path("/synthetic-overview-pool")


def v2_snapshot() -> FleetSnapshotV2:
    accounts = (
        FleetAccountV2(
            "codex-account", "Synthetic codex", Provider.OPENAI_CHATGPT,
            AuthKind.CHATGPT_SESSION, SecretState.CONFIGURED, LimitState.READY,
            True, None, None, None, None, None,
        ),
        FleetAccountV2(
            "gem-a", "Synthetic gem-a", Provider.GEMINI_API, AuthKind.API_KEY,
            SecretState.CONFIGURED, LimitState.READY, True, None, None, None,
            None, "synthetic-binding-a",
        ),
        FleetAccountV2(
            "gem-b", "Synthetic gem-b", Provider.GEMINI_API, AuthKind.API_KEY,
            SecretState.CONFIGURED, LimitState.READY, True, None, None, None,
            None, "synthetic-binding-b",
        ),
    )
    return FleetSnapshotV2(
        2,
        7,
        accounts,
        (
            FleetSeriesV2(
                "c", "Synthetic Codex", RunnerKind.CODEX_CLI,
                Provider.OPENAI_CHATGPT, "synthetic-codex", True, "generic",
                "standard", (
                    FleetSeriesMember(
                        "00000000-0000-4000-8000-000000000001",
                        1,
                        "codex-account",
                        True,
                    ),
                ),
            ),
            FleetSeriesV2(
                "g", "Synthetic Gemini", RunnerKind.GEMINI_CLI,
                Provider.GEMINI_API, "synthetic-gemini", True, "generic",
                "standard", (
                    FleetSeriesMember(
                        "00000000-0000-4000-8000-000000000002",
                        1,
                        "gem-a",
                        True,
                    ),
                    FleetSeriesMember(
                        "00000000-0000-4000-8000-000000000003",
                        2,
                        "gem-b",
                        True,
                    ),
                ),
            ),
        ),
    )


def v1_snapshot() -> FleetSnapshot:
    return FleetSnapshot(
        1,
        7,
        (
            FleetAccount(
                "codex-account", "Synthetic codex", Provider.OPENAI_CHATGPT,
                AuthKind.CHATGPT_SESSION, SecretState.CONFIGURED, LimitState.READY,
                True, None, None, None,
            ),
        ),
        (
            FleetSeries(
                "c", "Synthetic Codex", 1, RunnerKind.CODEX_CLI,
                Provider.OPENAI_CHATGPT, "synthetic-codex", "codex-account", True,
            ),
        ),
    )


SHORT_RESET = datetime(2026, 8, 15, 13, 0, tzinfo=timezone.utc)
WEEK_RESET = datetime(2026, 8, 22, 12, 0, tzinfo=timezone.utc)


def usage_account(
    account_id: str,
    *,
    stale: bool = False,
    limits: tuple[UsageLimit, ...] | None = None,
    cost_windows: tuple[UsageCostWindow, ...] = (),
) -> AccountUsage:
    return AccountUsage(
        account_id,
        "ok",
        CREATED,
        stale,
        () if limits is None else limits,
        cost_windows,
        (),
    )


def usage_triplet(account_id: str = "codex-account", *, source: str = "live") -> UsageSnapshot:
    limits = (
        UsageLimit("primary", 18000, 25.0, 75.0, SHORT_RESET),
        UsageLimit("primary", 604800, 40.0, 60.0, WEEK_RESET),
    )
    costs = (UsageCostWindow(3600, "primary", 18000, 12.5, "complete", 2),)
    return UsageSnapshot(
        (
            usage_account(
                account_id,
                stale=source == "cache",
                limits=limits,
                cost_windows=costs,
            ),
        ),
        source,
        source == "cache",
        (),
    )


def test_unique_live_usage_triplet_enriches_account_and_agent_rows() -> None:
    snapshot = v2_snapshot()
    inventory = build_inventory(snapshot, POOL)
    base = build_fleet_overview(snapshot, inventory, created_at=CREATED)
    enriched = enrich_fleet_overview_usage(base, usage_triplet())
    built = build_fleet_overview(
        snapshot, inventory, created_at=CREATED, usage_snapshot=usage_triplet()
    )

    account = enriched.account_limits[0]
    agent = enriched.agents[0]
    assert enriched == built
    assert enriched.integration_freshness == "fresh"
    assert enriched.warnings == ()
    assert (account.short_remaining_percent, account.week_remaining_percent) == (75.0, 60.0)
    assert account.short_reset_at == SHORT_RESET.isoformat()
    assert account.week_reset_at == WEEK_RESET.isoformat()
    assert account.cost_last_hour_percentage_points == 12.5
    assert account.usage_freshness == "fresh"
    assert agent.limit_short_remaining_percent == 75.0
    assert agent.limit_week_remaining_percent == 60.0
    assert agent.cost_last_hour_percentage_points == 12.5
    assert agent.usage_freshness == "fresh"


def test_enrichment_does_not_mutate_base_or_usage_and_ignores_input_permutations() -> None:
    snapshot = v2_snapshot()
    inventory = build_inventory(snapshot, POOL)
    base = build_fleet_overview(snapshot, inventory, created_at=CREATED)
    usage = replace(
        usage_triplet(),
        accounts=(
            usage_triplet().accounts[0],
            usage_account(
                "unmatched",
                limits=(UsageLimit("secondary", 3600, None, None, None),),
            ),
        ),
    )
    usage_before = usage
    base_before = base
    enriched = enrich_fleet_overview_usage(base, usage)
    permuted_account = usage.accounts[0]
    permuted_usage = UsageSnapshot(
        tuple(reversed(usage.accounts)),
        "live",
        False,
        (),
    )
    permuted_account = replace(
        permuted_account,
        limits=tuple(reversed(permuted_account.limits)),
        cost_windows=tuple(reversed(permuted_account.cost_windows)),
    )
    permuted_usage = replace(permuted_usage, accounts=(usage.accounts[1], permuted_account))

    assert enriched == enrich_fleet_overview_usage(base, permuted_usage)
    assert base == base_before
    assert usage == usage_before


@pytest.mark.parametrize(
    "bad_usage",
    [
        replace(usage_triplet(), warnings=("synthetic-detail",)),
        replace(usage_triplet(), source=[]),
        replace(
            usage_triplet(),
            accounts=(
                replace(
                    usage_triplet().accounts[0],
                    limits=(
                        replace(
                            usage_triplet().accounts[0].limits[0],
                            remaining_percent=float("nan"),
                        ),
                    ),
                ),
            ),
        ),
        replace(
            usage_triplet(),
            accounts=(
                replace(
                    usage_triplet().accounts[0],
                    limits=(
                        replace(
                            usage_triplet().accounts[0].limits[0],
                            used_percent=False,
                        ),
                    ),
                ),
            ),
        ),
        replace(
            usage_triplet(),
            accounts=(
                replace(
                    usage_triplet().accounts[0],
                    limits=(
                        replace(
                            usage_triplet().accounts[0].limits[0],
                            reset_at=datetime(2026, 8, 15, 13, 0),
                        ),
                    ),
                ),
            ),
        ),
        replace(usage_triplet(), source="live", stale=True),
        replace(usage_triplet(), source="cache", stale=False),
        replace(
            usage_triplet(),
            source="unavailable",
            stale=True,
            warnings=("usage_unavailable",),
        ),
        replace(usage_triplet(), source="unavailable", warnings=()),
    ],
    ids=[
        "arbitrary-warning",
        "unhashable-source",
        "nonfinite-percent",
        "bool-percent",
        "naive-reset",
        "live-stale-inconsistent",
        "cache-fresh-inconsistent",
        "unavailable-with-account",
        "unavailable-without-warning",
    ],
)
def test_usage_snapshot_contract_rejects_invalid_nested_dtos(bad_usage: UsageSnapshot) -> None:
    snapshot = v2_snapshot()
    base = build_fleet_overview(snapshot, build_inventory(snapshot, POOL), created_at=CREATED)
    with pytest.raises(FleetOverviewError, match="invalid_overview_input"):
        enrich_fleet_overview_usage(base, bad_usage)


def test_cache_usage_triplet_is_visible_but_stale() -> None:
    snapshot = v2_snapshot()
    overview = build_fleet_overview(
        snapshot,
        build_inventory(snapshot, POOL),
        created_at=CREATED,
        usage_snapshot=usage_triplet(source="cache"),
    )

    account = overview.account_limits[0]
    agent = overview.agents[0]
    assert overview.integration_freshness == "stale"
    assert (account.short_remaining_percent, account.week_remaining_percent) == (75.0, 60.0)
    assert account.cost_last_hour_percentage_points == 12.5
    assert account.usage_freshness == "stale"
    assert agent.usage_freshness == "stale"


@pytest.mark.parametrize("field", ["short", "week", "cost"])
@pytest.mark.parametrize("count", [0, 2])
def test_zero_or_ambiguous_usage_candidates_render_as_dash(field: str, count: int) -> None:
    limits = (
        UsageLimit("primary", 18000, 25.0, 75.0, SHORT_RESET),
        UsageLimit("primary", 604800, 40.0, 60.0, WEEK_RESET),
    )
    costs = (UsageCostWindow(3600, "primary", 18000, 12.5, "complete", 2),)
    if field == "short":
        limits = tuple(item for item in limits if item.window_seconds != 18000)
        if count == 2:
            limits += (
                UsageLimit("primary", 18000, 10.0, 90.0, SHORT_RESET),
                UsageLimit("primary", 18000, 20.0, 80.0, SHORT_RESET),
            )
    elif field == "week":
        limits = tuple(item for item in limits if item.window_seconds != 604800)
        if count == 2:
            limits += (
                UsageLimit("primary", 604800, 10.0, 90.0, WEEK_RESET),
                UsageLimit("primary", 604800, 20.0, 80.0, WEEK_RESET),
            )
    else:
        costs = () if count == 0 else (costs[0], costs[0])
    usage = UsageSnapshot((usage_account("codex-account", limits=limits, cost_windows=costs),), "live", False, ())
    snapshot = v2_snapshot()
    overview = build_fleet_overview(
        snapshot, build_inventory(snapshot, POOL), created_at=CREATED, usage_snapshot=usage
    )
    row = overview.account_limits[0]
    expected = None
    assert (row.short_remaining_percent if field == "short" else row.week_remaining_percent if field == "week" else row.cost_last_hour_percentage_points) == expected
    if field == "short":
        assert row.short_reset_at is None
        if count == 2:
            assert row.cost_last_hour_percentage_points is None
    if field == "week":
        assert row.week_reset_at is None


def test_cost_requires_exact_window_and_short_pool() -> None:
    snapshot = v2_snapshot()
    limits = (UsageLimit("primary", 18000, 25.0, 75.0, SHORT_RESET),)
    costs = (
        UsageCostWindow(3600, "other", 18000, 12.5, "complete", 2),
        UsageCostWindow(3600, "primary", 604800, 13.5, "complete", 2),
    )
    usage = UsageSnapshot((usage_account("codex-account", limits=limits, cost_windows=costs),), "live", False, ())
    overview = build_fleet_overview(
        snapshot, build_inventory(snapshot, POOL), created_at=CREATED, usage_snapshot=usage
    )
    assert overview.account_limits[0].cost_last_hour_percentage_points is None


def test_near_matching_account_id_and_missing_live_accounts_are_unavailable_without_warning() -> None:
    snapshot = v2_snapshot()
    usage = UsageSnapshot(
        (
            usage_account("codex-account-extra", limits=usage_triplet().accounts[0].limits),
        ),
        "live",
        False,
        (),
    )
    overview = build_fleet_overview(
        snapshot, build_inventory(snapshot, POOL), created_at=CREATED, usage_snapshot=usage
    )
    assert overview.warnings == ()
    assert all(row.usage_freshness == "unavailable" for row in overview.account_limits)
    assert all(row.short_remaining_percent is None for row in overview.account_limits)
    assert all(row.usage_freshness == "unavailable" for row in overview.agents)


def test_unavailable_usage_and_gemini_without_exact_match_stay_dash_without_extra_warning() -> None:
    snapshot = v2_snapshot()
    overview = build_fleet_overview(
        snapshot,
        build_inventory(snapshot, POOL),
        created_at=CREATED,
        usage_snapshot=UsageSnapshot((), "unavailable", True, ("usage_unavailable",)),
    )
    assert overview.integration_freshness == "unavailable"
    assert overview.warnings == ("usage_unavailable",)
    assert all(row.short_remaining_percent is None for row in overview.account_limits)
    assert all(row.cost_last_hour_percentage_points is None for row in overview.agents)


def test_explicit_none_usage_is_byte_and_semantically_identical_in_all_renderers() -> None:
    snapshot = v2_snapshot()
    inventory = build_inventory(snapshot, POOL)
    implicit = build_fleet_overview(snapshot, inventory, created_at=CREATED)
    explicit = build_fleet_overview(
        snapshot, inventory, created_at=CREATED, usage_snapshot=None
    )
    assert explicit == implicit
    assert fleet_overview_document(explicit) == fleet_overview_document(implicit)
    for format_name in ("json", "compact", "markdown"):
        assert render_fleet_overview(explicit, format=format_name) == render_fleet_overview(
            implicit, format=format_name
        )


def test_enrichment_rejects_malformed_exact_overview_rows_and_lookalikes() -> None:
    snapshot = v2_snapshot()
    base = build_fleet_overview(
        snapshot, build_inventory(snapshot, POOL), created_at=CREATED
    )

    class OverviewSubclass(FleetOverviewSnapshot):
        pass

    subclass = OverviewSubclass(
        base.generation,
        base.created_at,
        base.integration_freshness,
        base.series,
        base.agents,
        base.account_limits,
        base.warnings,
    )
    lookalike = SimpleNamespace(
        generation=base.generation,
        created_at=base.created_at,
        integration_freshness=base.integration_freshness,
        series=base.series,
        agents=base.agents,
        account_limits=base.account_limits,
        warnings=base.warnings,
    )
    malformed_rows = (
        replace(base, agents=(SimpleNamespace(account_id="codex-account"),)),
        replace(base, account_limits=(SimpleNamespace(account_id="codex-account"),)),
    )
    for candidate in (subclass, lookalike, *malformed_rows):
        with pytest.raises(FleetOverviewError, match="invalid_overview_input"):
            enrich_fleet_overview_usage(candidate, usage_triplet())


def test_v2_overview_groups_g_members_and_filters_inactive_context() -> None:
    snapshot = v2_snapshot()
    inventory = build_inventory(snapshot, POOL)
    overview = build_fleet_overview(
        snapshot,
        inventory,
        created_at=CREATED,
        contexts={
            "g1": FleetOverviewAgentContext(True, "running", "queen", "dispatch-7"),
            "g2": FleetOverviewAgentContext(False, "stopped"),
            "c1": FleetOverviewAgentContext(True, "idle"),
        },
    )
    assert [row.agent_id for row in overview.agents] == ["c1", "g1"]
    assert [(row.prefix, row.active_count, row.total_count) for row in overview.series] == [
        ("c", 1, 1),
        ("g", 1, 2),
    ]


def test_overview_v1_uses_inventory_account_and_default_context() -> None:
    snapshot = v1_snapshot()
    inventory = build_inventory(snapshot, POOL)
    overview = build_fleet_overview(snapshot, inventory, created_at=CREATED)
    assert overview.agents[0].account_label == "Synthetic codex"
    assert overview.agents[0].state == "unknown"
    assert overview.agents[0].usage_freshness == "unavailable"


def test_document_and_all_renderers_redact_binding_home_session_and_runner_path() -> None:
    snapshot = v2_snapshot()
    overview = build_fleet_overview(snapshot, build_inventory(snapshot, POOL), created_at=CREATED)
    document = fleet_overview_document(overview)
    rendered = "\n".join(
        render_fleet_overview(overview, format=name)
        for name in ("json", "compact", "markdown")
    )
    assert "binding" not in repr(document).lower()
    assert "synthetic-overview-pool" not in rendered
    assert "codex_agent_" not in rendered


def test_unknown_usage_is_explicit_and_rendered_as_dash() -> None:
    snapshot = v2_snapshot()
    overview = build_fleet_overview(snapshot, build_inventory(snapshot, POOL), created_at=CREATED)
    assert overview.warnings == ("usage_unavailable",)
    assert all(row.short_remaining_percent is None for row in overview.account_limits)
    assert "—" in render_fleet_overview(overview, format="compact")


def test_overview_is_mapping_order_independent_and_does_not_mutate_inputs() -> None:
    snapshot = v2_snapshot()
    inventory = build_inventory(snapshot, POOL)
    left = {
        "g1": FleetOverviewAgentContext(True, "running"),
        "c1": FleetOverviewAgentContext(True, "idle"),
    }
    right = dict(reversed(tuple(left.items())))
    assert build_fleet_overview(
        snapshot, inventory, created_at=CREATED, contexts=left,
    ) == build_fleet_overview(
        snapshot, inventory, created_at=CREATED, contexts=right,
    )
    assert tuple(left) == ("g1", "c1") and snapshot.generation == 7


def test_invalid_context_time_and_format_fail_closed_without_context_leak() -> None:
    snapshot = v2_snapshot()
    inventory = build_inventory(snapshot, POOL)
    with pytest.raises(FleetOverviewError, match="invalid_overview_context"):
        build_fleet_overview(
            snapshot,
            inventory,
            created_at=CREATED,
            contexts={"foreign": FleetOverviewAgentContext(True, "idle")},
        )
    with pytest.raises(FleetOverviewError, match="invalid_overview_input"):
        build_fleet_overview(
            snapshot,
            inventory,
            created_at=datetime(2026, 8, 15, 12, 0),
        )
    overview = build_fleet_overview(snapshot, inventory, created_at=CREATED)
    with pytest.raises(FleetOverviewError, match="invalid_overview_format"):
        render_fleet_overview(overview, format="html")


def test_hostile_context_mapping_normalizes_to_fixed_error() -> None:
    snapshot = v2_snapshot()
    inventory = build_inventory(snapshot, POOL)

    class HostileContexts(dict[str, FleetOverviewAgentContext]):
        def items(self):
            raise RuntimeError("synthetic-context-detail")

    with pytest.raises(FleetOverviewError) as raised:
        build_fleet_overview(
            snapshot,
            inventory,
            created_at=CREATED,
            contexts=HostileContexts({"c1": FleetOverviewAgentContext(True, "idle")}),
        )
    assert str(raised.value) == "invalid_overview_context"


def test_inventory_must_be_a_complete_bijective_snapshot_projection() -> None:
    snapshot = v2_snapshot()
    inventory = build_inventory(snapshot, POOL)
    malformed = (
        replace(inventory, agent_ids=("g1", "g2")),
        replace(inventory, agent_ids=("c1", "c1", "g1", "g2")),
        replace(inventory, agents={**inventory.agents, "foreign-agent": inventory.agents["c1"]}),
        replace(
            inventory,
            agents={
                **inventory.agents,
                "c1": replace(inventory.agents["c1"], agent_id="foreign-agent"),
            },
        ),
        replace(
            inventory,
            agents={
                **inventory.agents,
                "c1": replace(inventory.agents["c1"], series_prefix="g"),
            },
        ),
        replace(
            inventory,
            agents={
                **inventory.agents,
                "c1": replace(inventory.agents["c1"], ordinal=99),
            },
        ),
    )
    for candidate in malformed:
        with pytest.raises(FleetOverviewError) as raised:
            build_fleet_overview(snapshot, candidate, created_at=CREATED)
        assert str(raised.value) == "invalid_overview_input"


def test_document_and_renderers_reject_overview_and_row_lookalikes() -> None:
    snapshot = v2_snapshot()
    overview = build_fleet_overview(snapshot, build_inventory(snapshot, POOL), created_at=CREATED)

    class OverviewSubclass(FleetOverviewSnapshot):
        pass

    subclass = OverviewSubclass(
        overview.generation,
        overview.created_at,
        overview.integration_freshness,
        overview.series,
        overview.agents,
        overview.account_limits,
        overview.warnings,
    )
    generic = SimpleNamespace(
        generation=overview.generation,
        created_at=overview.created_at,
        integration_freshness=overview.integration_freshness,
        series=overview.series,
        agents=overview.agents,
        account_limits=overview.account_limits,
        warnings=overview.warnings,
    )
    marker = "synthetic-lookalike-marker"
    series_like = SimpleNamespace(
        prefix="x",
        display_name=marker,
        provider="synthetic",
        runner="synthetic",
        model="synthetic",
        active_count=1,
        total_count=1,
        agent_ids=("x1",),
    )
    agent_like = SimpleNamespace(
        agent_id=marker,
        series_display="synthetic",
        provider="synthetic",
        runner="synthetic",
        model="synthetic",
        account_id="synthetic-account",
        account_label=marker,
        state="unknown",
        principal_role=None,
        dispatch_id=None,
        limit_short_remaining_percent=None,
        limit_short_reset_at=None,
        limit_week_remaining_percent=None,
        limit_week_reset_at=None,
        cost_last_hour_percentage_points=None,
        usage_freshness="unavailable",
    )
    account_like = SimpleNamespace(
        account_id="synthetic-account",
        account_label=marker,
        provider="synthetic",
        short_remaining_percent=None,
        short_reset_at=None,
        week_remaining_percent=None,
        week_reset_at=None,
        cost_last_hour_percentage_points=None,
        usage_freshness="unavailable",
    )
    rows_like = FleetOverviewSnapshot(
        overview.generation,
        overview.created_at,
        overview.integration_freshness,
        (series_like,),
        (agent_like,),
        (account_like,),
        overview.warnings,
    )
    for candidate in (subclass, generic, rows_like):
        with pytest.raises(FleetOverviewError) as raised:
            fleet_overview_document(candidate)
        assert str(raised.value) == "invalid_overview_input"
        for format_name in ("json", "compact", "markdown", "html"):
            with pytest.raises(FleetOverviewError) as rendered:
                render_fleet_overview(candidate, format=format_name)
            assert str(rendered.value) == "invalid_overview_input"
            assert marker not in str(rendered.value)


def test_overview_row_dto_names_remain_exact_types() -> None:
    snapshot = v2_snapshot()
    overview = build_fleet_overview(snapshot, build_inventory(snapshot, POOL), created_at=CREATED)
    assert type(overview.series[0]) is FleetOverviewSeriesRow
    assert type(overview.agents[0]) is FleetOverviewAgentRow
    assert type(overview.account_limits[0]) is FleetOverviewAccountLimitRow
