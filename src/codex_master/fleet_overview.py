from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timedelta

from .fleet_registry import FleetSnapshot, FleetSnapshotV2, InventorySnapshot
from .usage_snapshot import (
    AccountUsage,
    UsageCostWindow,
    UsageLimit,
    UsageReset,
    UsageSnapshot,
)


class FleetOverviewError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class FleetOverviewAgentContext:
    active: bool
    state: str
    principal_role: str | None = None
    dispatch_id: str | None = None


@dataclass(frozen=True, slots=True)
class FleetOverviewAgentRow:
    agent_id: str
    series_display: str
    provider: str
    runner: str
    model: str
    account_id: str | None
    account_label: str | None
    state: str
    principal_role: str | None
    dispatch_id: str | None
    limit_short_remaining_percent: float | None
    limit_short_reset_at: str | None
    limit_week_remaining_percent: float | None
    limit_week_reset_at: str | None
    cost_last_hour_percentage_points: float | None
    usage_freshness: str
    limit_windows: tuple[UsageLimit, ...] = ()


@dataclass(frozen=True, slots=True)
class FleetOverviewSeriesRow:
    prefix: str
    display_name: str
    provider: str
    runner: str
    model: str
    active_count: int
    total_count: int
    agent_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class FleetOverviewAccountLimitRow:
    account_id: str
    account_label: str
    provider: str
    short_remaining_percent: float | None
    short_reset_at: str | None
    week_remaining_percent: float | None
    week_reset_at: str | None
    cost_last_hour_percentage_points: float | None
    usage_freshness: str
    limit_windows: tuple[UsageLimit, ...] = ()


@dataclass(frozen=True, slots=True)
class FleetOverviewSnapshot:
    generation: int
    created_at: datetime
    integration_freshness: str
    series: tuple[FleetOverviewSeriesRow, ...]
    agents: tuple[FleetOverviewAgentRow, ...]
    account_limits: tuple[FleetOverviewAccountLimitRow, ...]
    warnings: tuple[str, ...]


_ACCOUNT_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_TOKEN_RE = re.compile(r"^[!-~]{1,128}$")
_USAGE_STATUSES = frozenset({"ok", "partial", "error", "login_required", "unknown"})
_COST_COVERAGES = frozenset({"complete", "partial", "unknown"})


def _invalid_overview_input() -> None:
    raise FleetOverviewError("invalid_overview_input")


def _valid_usage_token(value: object, maximum: int) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= maximum
        and value.isascii()
        and _TOKEN_RE.fullmatch(value) is not None
    )


def _valid_usage_integer(value: object, maximum: int, *, allow_zero: bool = False) -> bool:
    minimum = 0 if allow_zero else 1
    return type(value) is int and minimum <= value <= maximum


def _valid_usage_percent(value: object) -> bool:
    if type(value) not in (int, float):
        return False
    try:
        numeric = float(value)
    except (OverflowError, ValueError):
        return False
    return math.isfinite(numeric) and 0 <= numeric <= 100


def _valid_usage_utc(value: object) -> bool:
    if type(value) is not datetime or value.tzinfo is None:
        return False
    try:
        offset = value.utcoffset()
    except Exception:
        return False
    return offset == timedelta(0)


def _context_for_agent(
    agent_id: str,
    descriptor: object,
    contexts: Mapping[str, FleetOverviewAgentContext],
) -> FleetOverviewAgentContext:
    context = contexts.get(agent_id)
    if context is not None:
        return context
    return FleetOverviewAgentContext(descriptor.enabled, "unknown")


def _account_limit_rows(snapshot: FleetSnapshot | FleetSnapshotV2) -> tuple[FleetOverviewAccountLimitRow, ...]:
    return tuple(
        FleetOverviewAccountLimitRow(
            account.account_id,
            account.label,
            account.provider.value,
            None,
            None,
            None,
            None,
            None,
            "unavailable",
        )
        for account in sorted(snapshot.accounts, key=lambda item: item.account_id)
    )


def _agent_row(
    descriptor: object,
    context: FleetOverviewAgentContext,
    series_by_prefix: Mapping[str, object],
    accounts_by_id: Mapping[str, object],
) -> FleetOverviewAgentRow:
    account = accounts_by_id.get(descriptor.account_id) if descriptor.account_id is not None else None
    series = series_by_prefix[descriptor.series_prefix]
    return FleetOverviewAgentRow(
        descriptor.agent_id,
        series.display_name,
        descriptor.provider.value,
        descriptor.runner.value,
        descriptor.model,
        descriptor.account_id,
        account.label if account is not None else None,
        context.state,
        context.principal_role,
        context.dispatch_id,
        None,
        None,
        None,
        None,
        None,
        "unavailable",
    )


def _series_rows(
    snapshot: FleetSnapshot | FleetSnapshotV2,
    inventory: InventorySnapshot,
    contexts: Mapping[str, FleetOverviewAgentContext],
) -> tuple[FleetOverviewSeriesRow, ...]:
    descriptors = tuple(inventory.agents[agent_id] for agent_id in inventory.agent_ids)
    rows: list[FleetOverviewSeriesRow] = []
    for series in sorted(snapshot.series, key=lambda item: item.prefix):
        members = tuple(
            sorted(
                (descriptor for descriptor in descriptors if descriptor.series_prefix == series.prefix),
                key=lambda descriptor: (descriptor.ordinal, descriptor.agent_id),
            )
        )
        rows.append(
            FleetOverviewSeriesRow(
                series.prefix,
                series.display_name,
                series.provider.value,
                series.runner.value,
                series.model,
                sum(_context_for_agent(item.agent_id, item, contexts).active for item in members),
                len(members),
                tuple(item.agent_id for item in members),
            )
        )
    return tuple(rows)


def _format_percent(value: float | None) -> str:
    return "—" if value is None else f"{value:.1f}%"


def _limit_label(limit: UsageLimit) -> str:
    if limit.window_seconds == 18_000:
        window = "5h"
    elif limit.window_seconds == 604_800:
        window = "7d"
    elif limit.window_seconds == 2_592_000:
        window = "30d"
    else:
        window = f"{limit.window_seconds}s"
    return f"{limit.pool}/{window}"


def _format_limit_windows(limits: tuple[UsageLimit, ...]) -> str:
    return ",".join(f"{_limit_label(item)}={_format_percent(item.remaining_percent)}" for item in limits) or "—"


def _validate_usage_snapshot(usage_snapshot: UsageSnapshot) -> None:
    try:
        if type(usage_snapshot) is not UsageSnapshot:
            _invalid_overview_input()
        source = usage_snapshot.source
        if type(source) is not str or source not in {"live", "cache", "unavailable"}:
            _invalid_overview_input()
        if (
            type(usage_snapshot.stale) is not bool
            or type(usage_snapshot.accounts) is not tuple
            or type(usage_snapshot.warnings) is not tuple
        ):
            _invalid_overview_input()
        if source == "live" and (usage_snapshot.stale or usage_snapshot.warnings != ()):
            _invalid_overview_input()
        if source == "cache" and (not usage_snapshot.stale or usage_snapshot.warnings != ()):
            _invalid_overview_input()
        if source == "unavailable" and (
            not usage_snapshot.stale
            or usage_snapshot.accounts != ()
            or usage_snapshot.warnings != ("usage_unavailable",)
        ):
            _invalid_overview_input()

        account_ids: set[str] = set()
        for account in usage_snapshot.accounts:
            if (
                type(account) is not AccountUsage
                or not _valid_usage_token(account.account_id, 64)
                or _ACCOUNT_ID_RE.fullmatch(account.account_id) is None
                or account.account_id in account_ids
                or not _valid_usage_utc(account.captured_at)
                or type(account.stale) is not bool
                or account.stale != (source == "cache")
                or type(account.status) is not str
                or account.status not in _USAGE_STATUSES
                or type(account.limits) is not tuple
                or type(account.cost_windows) is not tuple
                or type(account.usage_resets) is not tuple
                or type(account.limits) is not tuple
            ):
                _invalid_overview_input()
            account_ids.add(account.account_id)
            for limit in account.limits:
                if (
                    type(limit) is not UsageLimit
                    or not _valid_usage_token(limit.pool, 64)
                    or not _valid_usage_integer(limit.window_seconds, 2_592_000)
                    or limit.used_percent is not None
                    and not _valid_usage_percent(limit.used_percent)
                    or limit.remaining_percent is not None
                    and not _valid_usage_percent(limit.remaining_percent)
                    or limit.reset_at is not None
                    and not _valid_usage_utc(limit.reset_at)
                ):
                    _invalid_overview_input()
            for window in account.cost_windows:
                if (
                    type(window) is not UsageCostWindow
                    or not _valid_usage_integer(window.lookback_seconds, 86_400)
                    or not _valid_usage_token(window.pool, 64)
                    or not _valid_usage_integer(window.limit_window_seconds, 2_592_000)
                    or not _valid_usage_percent(window.consumed_percentage_points)
                    or type(window.coverage) is not str
                    or window.coverage not in _COST_COVERAGES
                    or not _valid_usage_integer(window.sample_count, 10_000, allow_zero=True)
                ):
                    _invalid_overview_input()
            for reset in account.usage_resets:
                if (
                    type(reset) is not UsageReset
                    or not _valid_usage_integer(reset.available, 10_000, allow_zero=True)
                    or type(reset.known) is not bool
                    or type(reset.redeem_capability) is not bool
                ):
                    _invalid_overview_input()
    except FleetOverviewError:
        raise
    except Exception:
        raise FleetOverviewError("invalid_overview_input") from None


def _validate_overview_rows(overview: FleetOverviewSnapshot) -> None:
    try:
        if (
            type(overview) is not FleetOverviewSnapshot
            or type(overview.series) is not tuple
            or type(overview.agents) is not tuple
            or type(overview.account_limits) is not tuple
            or type(overview.warnings) is not tuple
            or any(type(row) is not FleetOverviewSeriesRow for row in overview.series)
            or any(type(row) is not FleetOverviewAgentRow for row in overview.agents)
            or any(type(row) is not FleetOverviewAccountLimitRow for row in overview.account_limits)
            or any(type(row.account_id) not in (str, type(None)) for row in overview.agents)
            or any(type(row.account_id) is not str for row in overview.account_limits)
        ):
            _invalid_overview_input()
    except FleetOverviewError:
        raise
    except Exception:
        raise FleetOverviewError("invalid_overview_input") from None


def _usage_account_for_id(
    usage_snapshot: UsageSnapshot,
    account_id: str | None,
) -> AccountUsage | None:
    if account_id is None:
        return None
    matches = tuple(
        account for account in usage_snapshot.accounts if account.account_id == account_id
    )
    return matches[0] if len(matches) == 1 else None


def _reset_text(value: datetime | None) -> str | None:
    return value.isoformat() if isinstance(value, datetime) else None


def _usage_limit_document(limit: UsageLimit) -> dict[str, object]:
    return {
        "pool": limit.pool,
        "window_seconds": limit.window_seconds,
        "used_percent": limit.used_percent,
        "remaining_percent": limit.remaining_percent,
        "reset_at": _reset_text(limit.reset_at),
    }


def _usage_fields(
    usage_snapshot: UsageSnapshot,
    account_id: str | None,
) -> tuple[float | None, str | None, float | None, str | None, float | None, str, tuple[UsageLimit, ...]]:
    account = _usage_account_for_id(usage_snapshot, account_id)
    if (
        account is None
        or usage_snapshot.source == "unavailable"
        or (usage_snapshot.source == "live" and account.stale)
    ):
        return None, None, None, None, None, "unavailable", ()

    short_limits = tuple(
        limit for limit in account.limits if limit.pool == "primary" and limit.window_seconds == 18000
    ) or tuple(limit for limit in account.limits if limit.window_seconds == 18000)
    week_limits = tuple(limit for limit in account.limits if limit.pool == "primary" and limit.window_seconds == 604800)
    short = short_limits[0] if len(short_limits) == 1 else None
    week = week_limits[0] if len(week_limits) == 1 else None
    cost: UsageCostWindow | None = None
    if short is not None:
        cost_candidates = tuple(
            window
            for window in account.cost_windows
            if (
                window.lookback_seconds == 3600
                and window.limit_window_seconds == 18000
                and window.pool == short.pool
            )
        )
        if len(cost_candidates) == 1:
            cost = cost_candidates[0]
    freshness = "fresh" if usage_snapshot.source == "live" else "stale"
    return (
        short.remaining_percent if short is not None else None,
        _reset_text(short.reset_at) if short is not None else None,
        week.remaining_percent if week is not None else None,
        _reset_text(week.reset_at) if week is not None else None,
        cost.consumed_percentage_points if cost is not None else None,
        freshness,
        tuple(
            sorted(
                account.limits,
                key=lambda item: (item.pool, item.window_seconds, item.reset_at is not None, item.reset_at or datetime.min),
            )
        ),
    )


def enrich_fleet_overview_usage(
    overview: FleetOverviewSnapshot,
    usage_snapshot: UsageSnapshot,
) -> FleetOverviewSnapshot:
    try:
        _validate_overview_rows(overview)
        _validate_usage_snapshot(usage_snapshot)
        enriched_agents = tuple(
            replace(
                row,
                limit_short_remaining_percent=fields[0],
                limit_short_reset_at=fields[1],
                limit_week_remaining_percent=fields[2],
                limit_week_reset_at=fields[3],
                cost_last_hour_percentage_points=fields[4],
                usage_freshness=fields[5],
                limit_windows=fields[6],
            )
            for row in overview.agents
            for fields in (_usage_fields(usage_snapshot, row.account_id),)
        )
        enriched_accounts = tuple(
            replace(
                row,
                short_remaining_percent=fields[0],
                short_reset_at=fields[1],
                week_remaining_percent=fields[2],
                week_reset_at=fields[3],
                cost_last_hour_percentage_points=fields[4],
                usage_freshness=fields[5],
                limit_windows=fields[6],
            )
            for row in overview.account_limits
            for fields in (_usage_fields(usage_snapshot, row.account_id),)
        )
        integration_freshness = {
            "live": "fresh",
            "cache": "stale",
            "unavailable": "unavailable",
        }[usage_snapshot.source]
        return replace(
            overview,
            integration_freshness=integration_freshness,
            agents=enriched_agents,
            account_limits=enriched_accounts,
            warnings=usage_snapshot.warnings,
        )
    except FleetOverviewError:
        raise
    except Exception:
        raise FleetOverviewError("invalid_overview_input") from None


def build_fleet_overview(
    snapshot: FleetSnapshot | FleetSnapshotV2,
    inventory: InventorySnapshot,
    *,
    created_at: datetime,
    contexts: Mapping[str, FleetOverviewAgentContext] | None = None,
    active_only: bool = True,
    usage_snapshot: UsageSnapshot | None = None,
) -> FleetOverviewSnapshot:
    if (
        type(snapshot) not in (FleetSnapshot, FleetSnapshotV2)
        or type(inventory) is not InventorySnapshot
        or type(active_only) is not bool
        or not isinstance(created_at, datetime)
        or created_at.tzinfo is None
    ):
        raise FleetOverviewError("invalid_overview_input")
    try:
        timezone_offset = created_at.utcoffset()
    except Exception:
        raise FleetOverviewError("invalid_overview_input") from None
    if timezone_offset is None:
        raise FleetOverviewError("invalid_overview_input")

    if contexts is None:
        context_mapping: Mapping[str, FleetOverviewAgentContext] = {}
    elif not isinstance(contexts, Mapping):
        raise FleetOverviewError("invalid_overview_context")
    else:
        try:
            context_mapping = dict(contexts.items())
        except Exception:
            raise FleetOverviewError("invalid_overview_context") from None
        for agent_id, context in context_mapping.items():
            if agent_id not in inventory.agent_ids or type(context) is not FleetOverviewAgentContext:
                raise FleetOverviewError("invalid_overview_context")
            if (
                type(context.active) is not bool
                or not isinstance(context.state, str)
                or context.state not in {"running", "idle", "stopped", "unknown"}
                or any(
                    value is not None
                    and (not isinstance(value, str) or not 1 <= len(value) <= 80)
                    for value in (context.principal_role, context.dispatch_id)
                )
            ):
                raise FleetOverviewError("invalid_overview_context")

    accounts_by_id = {account.account_id: account for account in snapshot.accounts}
    series_by_prefix = {series.prefix: series for series in snapshot.series}
    try:
        expected_agent_metadata: dict[str, tuple[str, int]] = {}
        expected_agent_count = 0
        if type(snapshot) is FleetSnapshotV2:
            for series in snapshot.series:
                for member in series.members:
                    expected_agent_count += 1
                    expected_agent_metadata[f"{series.prefix}{member.ordinal}"] = (
                        series.prefix,
                        member.ordinal,
                    )
        else:
            for series in snapshot.series:
                for ordinal in range(1, series.count + 1):
                    expected_agent_count += 1
                    expected_agent_metadata[f"{series.prefix}{ordinal}"] = (
                        series.prefix,
                        ordinal,
                    )
        inventory_ids = tuple(inventory.agent_ids)
        inventory_keys = tuple(inventory.agents)
        if (
            len(expected_agent_metadata) != expected_agent_count
            or any(type(agent_id) is not str for agent_id in inventory_ids)
            or len(inventory_ids) != len(set(inventory_ids))
            or len(inventory_ids) != len(expected_agent_metadata)
            or set(inventory_ids) != set(expected_agent_metadata)
            or len(inventory_keys) != len(expected_agent_metadata)
            or set(inventory_keys) != set(expected_agent_metadata)
        ):
            raise FleetOverviewError("invalid_overview_input")
        descriptors = tuple(inventory.agents[agent_id] for agent_id in inventory.agent_ids)
        for agent_id, descriptor in zip(inventory_ids, descriptors):
            expected_prefix, expected_ordinal = expected_agent_metadata[agent_id]
            if (
                descriptor.agent_id != agent_id
                or descriptor.series_prefix != expected_prefix
                or descriptor.ordinal != expected_ordinal
            ):
                raise FleetOverviewError("invalid_overview_input")
    except Exception:
        raise FleetOverviewError("invalid_overview_input") from None
    if any(
        descriptor.series_prefix not in series_by_prefix
        or (
            descriptor.account_id is not None
            and descriptor.account_id not in accounts_by_id
        )
        for descriptor in descriptors
    ):
        raise FleetOverviewError("invalid_overview_input")

    ordered_descriptors = tuple(
        sorted(descriptors, key=lambda item: (item.series_prefix, item.ordinal, item.agent_id))
    )
    rows_with_context = tuple(
        (
            descriptor,
            _context_for_agent(descriptor.agent_id, descriptor, context_mapping),
        )
        for descriptor in ordered_descriptors
    )
    agent_rows = tuple(
        _agent_row(descriptor, context, series_by_prefix, accounts_by_id)
        for descriptor, context in rows_with_context
        if not active_only or context.active
    )
    base_overview = FleetOverviewSnapshot(
        snapshot.generation,
        created_at,
        "registry_only",
        _series_rows(snapshot, inventory, context_mapping),
        agent_rows,
        _account_limit_rows(snapshot),
        ("usage_unavailable",),
    )
    if usage_snapshot is None:
        return base_overview
    return enrich_fleet_overview_usage(base_overview, usage_snapshot)


def fleet_overview_document(overview: FleetOverviewSnapshot) -> dict[str, object]:
    try:
        valid_overview = (
            type(overview) is FleetOverviewSnapshot
            and all(type(row) is FleetOverviewSeriesRow for row in overview.series)
            and all(type(row) is FleetOverviewAgentRow for row in overview.agents)
            and all(type(row) is FleetOverviewAccountLimitRow for row in overview.account_limits)
        )
    except Exception:
        valid_overview = False
    if not valid_overview:
        raise FleetOverviewError("invalid_overview_input")
    return {
        "generation": overview.generation,
        "created_at": overview.created_at.isoformat(),
        "integration_freshness": overview.integration_freshness,
        "series": [
            {
                "prefix": row.prefix,
                "display_name": row.display_name,
                "provider": row.provider,
                "runner": row.runner,
                "model": row.model,
                "active_count": row.active_count,
                "total_count": row.total_count,
                "agent_ids": list(row.agent_ids),
            }
            for row in overview.series
        ],
        "agents": [
            {
                "agent_id": row.agent_id,
                "series_display": row.series_display,
                "provider": row.provider,
                "runner": row.runner,
                "model": row.model,
                "account_id": row.account_id,
                "account_label": row.account_label,
                "state": row.state,
                "principal_role": row.principal_role,
                "dispatch_id": row.dispatch_id,
                "limit_short_remaining_percent": row.limit_short_remaining_percent,
                "limit_short_reset_at": row.limit_short_reset_at,
                "limit_week_remaining_percent": row.limit_week_remaining_percent,
                "limit_week_reset_at": row.limit_week_reset_at,
                "cost_last_hour_percentage_points": row.cost_last_hour_percentage_points,
                "usage_freshness": row.usage_freshness,
                "limit_windows": [_usage_limit_document(item) for item in row.limit_windows],
            }
            for row in overview.agents
        ],
        "account_limits": [
            {
                "account_id": row.account_id,
                "account_label": row.account_label,
                "provider": row.provider,
                "short_remaining_percent": row.short_remaining_percent,
                "short_reset_at": row.short_reset_at,
                "week_remaining_percent": row.week_remaining_percent,
                "week_reset_at": row.week_reset_at,
                "cost_last_hour_percentage_points": row.cost_last_hour_percentage_points,
                "usage_freshness": row.usage_freshness,
                "limit_windows": [_usage_limit_document(item) for item in row.limit_windows],
            }
            for row in overview.account_limits
        ],
        "warnings": list(overview.warnings),
    }


def render_fleet_overview(
    overview: FleetOverviewSnapshot,
    *,
    format: str,
) -> str:
    try:
        valid_overview = (
            type(overview) is FleetOverviewSnapshot
            and all(type(row) is FleetOverviewSeriesRow for row in overview.series)
            and all(type(row) is FleetOverviewAgentRow for row in overview.agents)
            and all(type(row) is FleetOverviewAccountLimitRow for row in overview.account_limits)
        )
    except Exception:
        valid_overview = False
    if not valid_overview:
        raise FleetOverviewError("invalid_overview_input")
    if not isinstance(format, str) or format not in {"json", "compact", "markdown"}:
        raise FleetOverviewError("invalid_overview_format")
    if format == "json":
        return json.dumps(
            fleet_overview_document(overview),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    if format == "compact":
        lines = [
            f"Fleet overview generation={overview.generation} freshness={overview.integration_freshness}",
        ]
        lines.extend(
            f"series {row.prefix} {row.display_name} active={row.active_count}/{row.total_count} agents={','.join(row.agent_ids)}"
            for row in overview.series
        )
        lines.extend(
            f"agent {row.agent_id} state={row.state} provider={row.provider} runner={row.runner} model={row.model}"
            for row in overview.agents
        )
        lines.extend(
            f"account {row.account_id} short={_format_percent(row.short_remaining_percent)} "
            f"week={_format_percent(row.week_remaining_percent)} "
            f"limits={_format_limit_windows(row.limit_windows)} "
            f"cost={_format_percent(row.cost_last_hour_percentage_points)}"
            for row in overview.account_limits
        )
        lines.append(f"warnings={','.join(overview.warnings)}")
        return "\n".join(lines)

    lines = [
        "# Fleet Overview",
        f"Generation: {overview.generation}",
        f"Freshness: {overview.integration_freshness}",
        "",
        "## Series",
        "| Prefix | Display | Active | Total | Agents |",
        "| --- | --- | ---: | ---: | --- |",
    ]
    lines.extend(
        f"| {row.prefix} | {row.display_name} | {row.active_count} | {row.total_count} | "
        f"{', '.join(row.agent_ids)} |"
        for row in overview.series
    )
    lines.extend(
        [
            "",
            "## Agents",
            "| Agent | Series | State | Provider | Runner | Model |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )
    lines.extend(
        f"| {row.agent_id} | {row.series_display} | {row.state} | {row.provider} | "
        f"{row.runner} | {row.model} |"
        for row in overview.agents
    )
    lines.extend(
        [
            "",
            "## Account limits",
            "| Account | Label | Provider | Limits | Cost/hour |",
            "| --- | --- | --- | --- | ---: |",
        ]
    )
    lines.extend(
        f"| {row.account_id} | {row.account_label} | {row.provider} | "
        f"{_format_limit_windows(row.limit_windows)} | "
        f"{_format_percent(row.cost_last_hour_percentage_points)} |"
        for row in overview.account_limits
    )
    lines.extend(("", f"Warnings: {', '.join(overview.warnings)}"))
    return "\n".join(lines)
