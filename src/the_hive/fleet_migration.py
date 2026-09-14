from __future__ import annotations

from collections.abc import Collection, Mapping
from dataclasses import dataclass

from .fleet_registry import FleetMigrationSnapshot, Provider


class GMigrationPlanError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class GMigrationMember:
    migration_identity: str
    source_prefix: str
    source_ordinal: int
    account_id: str
    target_ordinal: int | None
    disposition: str
    reason_code: str


@dataclass(frozen=True, slots=True)
class GSeriesMigrationPlan:
    source_generation: int
    target_prefix: str
    g_relocation_target: str | None
    members: tuple[GMigrationMember, ...]


def _gemini_candidates(
    snapshot: FleetMigrationSnapshot,
    accounts_by_id: Mapping[str, object],
) -> tuple[tuple[str, str, int, str, str], ...]:
    candidates: list[tuple[str, str, int, str, str]] = []
    for series in snapshot.series:
        if series.provider is not Provider.GEMINI_API:
            continue
        for member in series.members:
            account = accounts_by_id.get(member.account_id)
            if account is None or not isinstance(member.account_id, str):
                raise GMigrationPlanError("credential_binding_unknown")
            if (
                not isinstance(member.migration_identity, str)
                or not isinstance(series.prefix, str)
                or isinstance(member.ordinal, bool)
                or not isinstance(member.ordinal, int)
                or not isinstance(account.label, str)
            ):
                raise GMigrationPlanError("invalid_migration_snapshot")
            candidates.append(
                (
                    member.migration_identity,
                    series.prefix,
                    member.ordinal,
                    member.account_id,
                    account.label,
                )
            )
    return tuple(candidates)


def _binding_for_account(
    credential_bindings: Mapping[str, str],
    account_id: str,
) -> str:
    if not isinstance(credential_bindings, Mapping):
        raise GMigrationPlanError("credential_binding_unknown")
    try:
        binding = credential_bindings.get(account_id)
    except Exception:
        raise GMigrationPlanError("credential_binding_unknown") from None
    if not isinstance(binding, str) or not 1 <= len(binding) <= 512:
        raise GMigrationPlanError("credential_binding_unknown")
    return binding


def _sorted_candidate_key(candidate: tuple[str, str, int, str, str]) -> tuple[str, str, str]:
    migration_identity, _source_prefix, _source_ordinal, account_id, label = candidate
    return label.casefold(), account_id, migration_identity


def _g_relocation_target(
    snapshot: FleetMigrationSnapshot,
) -> str | None:
    prefixes = {series.prefix for series in snapshot.series}
    g_series = next((series for series in snapshot.series if series.prefix == "g"), None)
    if g_series is None or g_series.provider is Provider.GEMINI_API:
        return None
    gemini_prefixes = sorted(
        series.prefix
        for series in snapshot.series
        if series.provider is Provider.GEMINI_API and series.prefix != "g"
    )
    if gemini_prefixes:
        return gemini_prefixes[0]
    for ordinal in range(ord("a"), ord("z") + 1):
        prefix = chr(ordinal)
        if prefix not in prefixes:
            return prefix
    ordinal = 1
    while f"g-swap-{ordinal}" in prefixes:
        ordinal += 1
    return f"g-swap-{ordinal}"


def plan_g_series_migration(
    snapshot: FleetMigrationSnapshot,
    *,
    credential_bindings: Mapping[str, str],
    active_migration_identities: Collection[str] = (),
) -> GSeriesMigrationPlan:
    if (
        type(snapshot) is not FleetMigrationSnapshot
        or type(snapshot.source_schema_version) is not int
        or snapshot.source_schema_version != 1
    ):
        raise GMigrationPlanError("invalid_migration_snapshot")

    accounts_by_id = {account.account_id: account for account in snapshot.accounts}
    candidates = _gemini_candidates(snapshot, accounts_by_id)
    if not candidates:
        raise GMigrationPlanError("no_gemini_series")
    candidate_identities = tuple(candidate[0] for candidate in candidates)
    if len(set(candidate_identities)) != len(candidate_identities):
        raise GMigrationPlanError("invalid_migration_snapshot")

    grouped: dict[str, list[tuple[str, str, int, str, str]]] = {}
    for candidate in candidates:
        _migration_identity, _source_prefix, _source_ordinal, account_id, _label = candidate
        binding = _binding_for_account(credential_bindings, account_id)
        grouped.setdefault(binding, []).append(candidate)

    if isinstance(active_migration_identities, str) or not isinstance(
        active_migration_identities, Collection
    ):
        raise GMigrationPlanError("invalid_active_migration_identity")
    try:
        active_values = tuple(active_migration_identities)
    except Exception:
        raise GMigrationPlanError("invalid_active_migration_identity") from None
    if any(not isinstance(identity, str) for identity in active_values):
        raise GMigrationPlanError("invalid_active_migration_identity")
    if len(set(active_values)) != len(active_values):
        raise GMigrationPlanError("invalid_active_migration_identity")
    candidate_identity_set = set(candidate_identities)
    if any(identity not in candidate_identity_set for identity in active_values):
        raise GMigrationPlanError("invalid_active_migration_identity")
    active = frozenset(active_values)

    winners: list[tuple[str, str, int, str, str]] = []
    retired: list[GMigrationMember] = []
    for group in grouped.values():
        active_group = [candidate for candidate in group if candidate[0] in active]
        if len(active_group) > 1:
            raise GMigrationPlanError("multiple_active_credential_bindings")
        winner = active_group[0] if active_group else min(group, key=_sorted_candidate_key)
        winners.append(winner)
        for candidate in group:
            if candidate != winner:
                retired.append(
                    GMigrationMember(
                        candidate[0],
                        candidate[1],
                        candidate[2],
                        candidate[3],
                        None,
                        "retired_duplicate_credential",
                        "duplicate_credential",
                    )
                )

    g_ordinal_counts: dict[int, int] = {}
    for winner in winners:
        if winner[1] == "g" and winner[2] > 0:
            g_ordinal_counts[winner[2]] = g_ordinal_counts.get(winner[2], 0) + 1

    used_ordinals: set[int] = set()
    selected: list[GMigrationMember] = []
    for winner in winners:
        if (
            winner[1] == "g"
            and winner[2] > 0
            and g_ordinal_counts[winner[2]] == 1
            and winner[2] not in used_ordinals
        ):
            used_ordinals.add(winner[2])
            selected.append(
                GMigrationMember(
                    winner[0], winner[1], winner[2], winner[3], winner[2], "g_member", "selected"
                )
            )

    for winner in sorted(
        (candidate for candidate in winners if candidate[0] not in {item.migration_identity for item in selected}),
        key=_sorted_candidate_key,
    ):
        target_ordinal = 1
        while target_ordinal in used_ordinals:
            target_ordinal += 1
        used_ordinals.add(target_ordinal)
        selected.append(
            GMigrationMember(
                winner[0], winner[1], winner[2], winner[3], target_ordinal, "g_member", "selected"
            )
        )

    members = tuple(
        sorted(
            (*selected, *retired),
            key=lambda item: (
                item.target_ordinal is None,
                item.target_ordinal or 0,
                item.migration_identity,
            ),
        )
    )
    return GSeriesMigrationPlan(
        snapshot.generation,
        "g",
        _g_relocation_target(snapshot),
        members,
    )
