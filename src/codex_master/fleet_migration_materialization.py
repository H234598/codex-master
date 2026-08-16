from __future__ import annotations

from collections.abc import Callable as _Callable, Collection as _Collection, Mapping as _Mapping
from dataclasses import dataclass as _dataclass
from uuid import UUID as _UUID

from .fleet_migration import GMigrationMember as _GMigrationMember
from .fleet_migration import GSeriesMigrationPlan as _GSeriesMigrationPlan
from .fleet_registry import AuthKind as _AuthKind
from .fleet_registry import FleetAccount as _FleetAccount
from .fleet_registry import FleetAccountV2 as _FleetAccountV2
from .fleet_registry import FleetMigrationSeries as _FleetMigrationSeries
from .fleet_registry import FleetMigrationSnapshot as _FleetMigrationSnapshot
from .fleet_registry import FleetSeriesMember as _FleetSeriesMember
from .fleet_registry import FleetSeriesV2 as _FleetSeriesV2
from .fleet_registry import FleetSnapshotV2 as _FleetSnapshotV2
from .fleet_registry import LegacyFleetSeriesMember as _LegacyFleetSeriesMember
from .fleet_registry import LimitState as _LimitState
from .fleet_registry import Provider as _Provider
from .fleet_registry import RunnerKind as _RunnerKind
from .fleet_registry import SecretState as _SecretState
from .fleet_registry import fleet_document as _fleet_document
from .fleet_registry import normalize_fleet_document as _normalize_fleet_document


class GMigrationMaterializationError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@_dataclass(frozen=True, slots=True)
class MemberIdAllocation:
    migration_identity: str
    member_id: str


def _fail(code: str) -> None:
    raise GMigrationMaterializationError(code)


def _canonical_uuid4(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = _UUID(value)
    except (AttributeError, ValueError):
        return None
    if parsed.version != 4 or str(parsed) != value:
        return None
    return value


def _uuid_value(value: object) -> str | None:
    if type(value) is not _UUID:
        return None
    return _canonical_uuid4(str(value))


def _valid_text(value: object, *, minimum: int = 1, maximum: int = 512) -> bool:
    return isinstance(value, str) and minimum <= len(value) <= maximum


def _valid_optional_text(value: object, *, maximum: int = 200) -> bool:
    return value is None or _valid_text(value, maximum=maximum)


def _valid_provider_runner(provider: object, runner: object) -> bool:
    expected = {
        _Provider.OPENAI_CHATGPT: _RunnerKind.CODEX_CLI,
        _Provider.OPENAI_API: _RunnerKind.CODEX_CLI,
        _Provider.GEMINI_API: _RunnerKind.GEMINI_CLI,
        _Provider.OLLAMA_LOCAL: _RunnerKind.CODEX_CLI,
        _Provider.HUGGINGFACE_INFERENCE: _RunnerKind.CODEX_CLI,
    }
    return type(provider) is _Provider and type(runner) is _RunnerKind and expected.get(provider) is runner


def _valid_account(account: object) -> bool:
    if type(account) is not _FleetAccount:
        return False
    return (
        _valid_text(account.account_id, maximum=64)
        and _valid_text(account.label, maximum=120)
        and type(account.provider) is _Provider
        and type(account.auth_kind) is _AuthKind
        and type(account.secret_state) is _SecretState
        and type(account.limit_state) is _LimitState
        and type(account.enabled) is bool
        and (account.reset_at_utc is None or _valid_text(account.reset_at_utc, maximum=64))
        and (account.last_probe_at_utc is None or _valid_text(account.last_probe_at_utc, maximum=64))
        and (account.limit_reason is None or _valid_text(account.limit_reason, maximum=64))
        and (account.billing_group is None or _valid_text(account.billing_group, maximum=64))
    )


def _valid_member(member: object) -> bool:
    if type(member) is not _GMigrationMember:
        return False
    return (
        _valid_text(member.migration_identity, maximum=512)
        and _valid_text(member.source_prefix, maximum=16)
        and type(member.source_ordinal) is int
        and member.source_ordinal > 0
        and _valid_text(member.account_id, maximum=64)
        and (member.target_ordinal is None or (type(member.target_ordinal) is int and member.target_ordinal > 0))
        and _valid_text(member.disposition, maximum=64)
        and _valid_text(member.reason_code, maximum=64)
    )


def _validate_snapshot_shape(snapshot: object) -> tuple[dict[str, _FleetAccount], dict[str, tuple[_FleetMigrationSeries, object]]]:
    if type(snapshot) is not _FleetMigrationSnapshot:
        _fail("invalid_migration_materialization")
    if (
        type(snapshot.source_schema_version) is not int
        or snapshot.source_schema_version != 1
        or type(snapshot.generation) is not int
        or snapshot.generation <= 0
        or type(snapshot.accounts) is not tuple
        or type(snapshot.series) is not tuple
    ):
        _fail("invalid_migration_materialization")
    accounts: dict[str, _FleetAccount] = {}
    for account in snapshot.accounts:
        if not _valid_account(account) or account.account_id in accounts:
            _fail("invalid_migration_materialization")
        accounts[account.account_id] = account
    members: dict[str, tuple[_FleetMigrationSeries, object]] = {}
    prefixes: set[str] = set()
    for series in snapshot.series:
        if (
            type(series) is not _FleetMigrationSeries
            or not _valid_text(series.prefix, maximum=16)
            or series.prefix in prefixes
            or not _valid_text(series.display_name, maximum=120)
            or not _valid_provider_runner(series.provider, series.runner)
            or not _valid_text(series.model, maximum=200)
            or type(series.enabled) is not bool
            or not _valid_text(series.skill_profile, maximum=64)
            or not _valid_text(series.task_profile, maximum=64)
            or type(series.members) is not tuple
            or not series.members
        ):
            _fail("invalid_migration_materialization")
        prefixes.add(series.prefix)
        for legacy_member in series.members:
            if (
                type(legacy_member) is not _LegacyFleetSeriesMember
                or not _valid_text(legacy_member.migration_identity, maximum=512)
                or type(legacy_member.ordinal) is not int
                or legacy_member.ordinal <= 0
                or legacy_member.account_id is not None
                and not _valid_text(legacy_member.account_id, maximum=64)
                or type(legacy_member.enabled) is not bool
                or not _valid_optional_text(legacy_member.model_override)
                or not _valid_optional_text(legacy_member.skill_profile_override, maximum=64)
                or not _valid_optional_text(legacy_member.task_profile_override, maximum=64)
                or legacy_member.migration_identity in members
            ):
                _fail("invalid_migration_materialization")
            members[legacy_member.migration_identity] = (series, legacy_member)
    return accounts, members


def _validate_provider_references(
    accounts: _Mapping[str, _FleetAccount],
    members: _Mapping[str, tuple[_FleetMigrationSeries, object]],
) -> None:
    for series, legacy_member in members.values():
        account = accounts.get(legacy_member.account_id) if legacy_member.account_id is not None else None
        requires_account = series.provider is not _Provider.OLLAMA_LOCAL
        if (requires_account and account is None) or (not requires_account and account is not None):
            _fail("invalid_migration_materialization")
        if account is not None and account.provider is not series.provider:
            _fail("invalid_migration_materialization")


def _expected_relocation(snapshot: _FleetMigrationSnapshot) -> str | None:
    prefixes = {series.prefix for series in snapshot.series}
    g_series = next((series for series in snapshot.series if series.prefix == "g"), None)
    if g_series is None or g_series.provider is _Provider.GEMINI_API:
        return None
    gemini_prefixes = sorted(
        series.prefix
        for series in snapshot.series
        if series.provider is _Provider.GEMINI_API and series.prefix != "g"
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


def _validate_plan(
    snapshot: _FleetMigrationSnapshot,
    plan: object,
    members: _Mapping[str, tuple[_FleetMigrationSeries, object]],
) -> dict[str, _GMigrationMember]:
    if type(plan) is not _GSeriesMigrationPlan:
        _fail("invalid_migration_plan")
    if (
        type(plan.source_generation) is not int
        or plan.source_generation != snapshot.generation
        or plan.target_prefix != "g"
        or (plan.g_relocation_target is not None and not _valid_text(plan.g_relocation_target, maximum=16))
        or type(plan.members) is not tuple
    ):
        _fail("invalid_migration_plan")
    if plan.g_relocation_target != _expected_relocation(snapshot):
        _fail("invalid_migration_plan")
    gemini_members = {
        identity: (series, legacy_member)
        for identity, (series, legacy_member) in members.items()
        if series.provider is _Provider.GEMINI_API
    }
    by_identity: dict[str, _GMigrationMember] = {}
    target_ordinals: set[int] = set()
    for item in plan.members:
        if not _valid_member(item) or item.migration_identity in by_identity:
            _fail("invalid_migration_plan")
        source = gemini_members.get(item.migration_identity)
        if source is None:
            _fail("invalid_migration_plan")
        source_series, source_member = source
        if (
            item.source_prefix != source_series.prefix
            or item.source_ordinal != source_member.ordinal
            or item.account_id != source_member.account_id
        ):
            _fail("invalid_migration_plan")
        if item.disposition == "g_member":
            if item.reason_code != "selected" or item.target_ordinal is None:
                _fail("invalid_migration_plan")
            if item.target_ordinal in target_ordinals:
                _fail("invalid_migration_plan")
            target_ordinals.add(item.target_ordinal)
        elif item.disposition == "retired_duplicate_credential":
            if item.target_ordinal is not None or item.reason_code != "duplicate_credential":
                _fail("invalid_migration_plan")
        else:
            _fail("invalid_migration_plan")
        by_identity[item.migration_identity] = item
    if set(by_identity) != set(gemini_members):
        _fail("invalid_migration_plan")
    if not any(item.disposition == "g_member" for item in by_identity.values()):
        _fail("invalid_migration_plan")
    return by_identity


def _final_identities(
    members: _Mapping[str, tuple[_FleetMigrationSeries, object]],
    plan: _Mapping[str, _GMigrationMember],
) -> tuple[str, ...]:
    identities = {
        identity
        for identity, (series, _member) in members.items()
        if series.provider is not _Provider.GEMINI_API
    }
    identities.update(
        identity for identity, item in plan.items() if item.disposition == "g_member"
    )
    return tuple(sorted(identities))


def _allocation_entries(value: object, *, code: str) -> tuple[tuple[str, str], ...]:
    if type(value) is not tuple:
        _fail(code)
    entries: list[tuple[str, str]] = []
    for record in value:
        if (
            type(record) is not MemberIdAllocation
            or type(record.migration_identity) is not str
            or _canonical_uuid4(record.member_id) is None
        ):
            _fail(code)
        entries.append((record.migration_identity, record.member_id))
    identities = tuple(identity for identity, _member_id in entries)
    if identities != tuple(sorted(identities)) or len(set(identities)) != len(identities):
        _fail(code)
    return tuple(entries)


def _journaled_by_identity(
    journaled: object,
    final_identities: tuple[str, ...],
) -> dict[str, str]:
    entries = _allocation_entries(journaled, code="invalid_member_id_allocation")
    final_set = set(final_identities)
    result: dict[str, str] = {}
    used: set[str] = set()
    for identity, member_id in entries:
        if identity not in final_set or identity in result:
            _fail("invalid_member_id_allocation")
        canonical = _canonical_uuid4(member_id)
        if canonical is None or canonical in used:
            _fail("invalid_member_id_allocation")
        result[identity] = canonical
        used.add(canonical)
    return result


def allocate_final_member_ids(
    snapshot: _FleetMigrationSnapshot,
    plan: _GSeriesMigrationPlan,
    *,
    journaled: _Collection[MemberIdAllocation] = (),
    uuid4: _Callable[[], _UUID],
) -> tuple[MemberIdAllocation, ...]:
    try:
        accounts, members = _validate_snapshot_shape(snapshot)
        _validate_provider_references(accounts, members)
        validated_plan = _validate_plan(snapshot, plan, members)
        final_identities = _final_identities(members, validated_plan)
        existing = _journaled_by_identity(journaled, final_identities)
        used = set(existing.values())
        result: list[MemberIdAllocation] = []
        for identity in final_identities:
            if identity in existing:
                result.append(MemberIdAllocation(identity, existing[identity]))
                continue
            try:
                value = uuid4()
            except Exception:
                _fail("invalid_member_id_allocation")
            member_id = _uuid_value(value)
            if member_id is None or member_id in used:
                _fail("invalid_member_id_allocation")
            used.add(member_id)
            result.append(MemberIdAllocation(identity, member_id))
        return tuple(result)
    except GMigrationMaterializationError:
        raise
    except Exception:
        raise GMigrationMaterializationError("invalid_migration_materialization") from None


def _binding_by_account(
    snapshot: _FleetMigrationSnapshot,
    credential_bindings: object,
) -> dict[str, str]:
    if not isinstance(credential_bindings, _Mapping) or isinstance(credential_bindings, (str, bytes)):
        _fail("credential_binding_unknown")
    gemini_ids = {
        account.account_id for account in snapshot.accounts if account.provider is _Provider.GEMINI_API
    }
    try:
        entries = tuple(credential_bindings.items())
    except Exception:
        _fail("credential_binding_unknown")
    if len(entries) != len(gemini_ids) or {key for key, _value in entries} != gemini_ids:
        _fail("credential_binding_unknown")
    result: dict[str, str] = {}
    for key, value in entries:
        if (
            type(key) is not str
            or type(value) is not str
            or len(value) != len("hmac-sha256:") + 64
            or not value.startswith("hmac-sha256:")
            or any(char not in "0123456789abcdef" for char in value[len("hmac-sha256:") :])
        ):
            _fail("credential_binding_unknown")
        result[key] = value
    return result


def _duplicate_loser_accounts(
    snapshot: _FleetMigrationSnapshot,
    members: _Mapping[str, tuple[_FleetMigrationSeries, object]],
    plan: _Mapping[str, _GMigrationMember],
    bindings: _Mapping[str, str],
) -> set[str]:
    grouped: dict[str, set[str]] = {}
    for account_id, binding in bindings.items():
        grouped.setdefault(binding, set()).add(account_id)
    non_gemini_references = {
        legacy_member.account_id
        for series, legacy_member in members.values()
        if series.provider is not _Provider.GEMINI_API and legacy_member.account_id is not None
    }
    losers: set[str] = set()
    for binding, account_ids in grouped.items():
        if len(account_ids) < 2:
            continue
        winners = {
            item.account_id
            for identity, item in plan.items()
            if item.disposition == "g_member" and bindings.get(item.account_id) == binding
        }
        if len(winners) != 1:
            _fail("migration_duplicate_account_conflict")
        winner = next(iter(winners))
        for account_id in account_ids - {winner}:
            account_members = [
                identity
                for identity, (series, legacy_member) in members.items()
                if series.provider is _Provider.GEMINI_API and legacy_member.account_id == account_id
            ]
            if (
                not account_members
                or any(plan[identity].disposition != "retired_duplicate_credential" for identity in account_members)
                or account_id in non_gemini_references
            ):
                _fail("migration_duplicate_account_conflict")
            losers.add(account_id)
    return losers


def _materialize_accounts(
    snapshot: _FleetMigrationSnapshot,
    bindings: _Mapping[str, str],
    disabled_duplicate_accounts: set[str],
) -> tuple[_FleetAccountV2, ...]:
    return tuple(
        _FleetAccountV2(
            account.account_id,
            account.label,
            account.provider,
            account.auth_kind,
            account.secret_state,
            account.limit_state,
            account.enabled and account.account_id not in disabled_duplicate_accounts,
            account.reset_at_utc,
            account.last_probe_at_utc,
            account.limit_reason,
            account.billing_group,
            bindings.get(account.account_id) if account.provider is _Provider.GEMINI_API else None,
        )
        for account in snapshot.accounts
    )


def _override(value: str | None, source_default: str, target_default: str) -> str | None:
    effective = source_default if value is None else value
    return None if effective == target_default else effective


def _materialize_series(
    snapshot: _FleetMigrationSnapshot,
    members: _Mapping[str, tuple[_FleetMigrationSeries, object]],
    plan: _Mapping[str, _GMigrationMember],
    allocations: _Mapping[str, str],
    accounts: _Mapping[str, _FleetAccountV2],
) -> tuple[_FleetSeriesV2, ...]:
    output: list[_FleetSeriesV2] = []
    for source_series in sorted(snapshot.series, key=lambda item: item.prefix):
        if source_series.provider is _Provider.GEMINI_API:
            continue
        prefix = source_series.prefix
        if source_series.prefix == "g":
            prefix = _expected_relocation(snapshot)
            if prefix is None:
                _fail("invalid_migration_plan")
        output_members = []
        for legacy_member in sorted(source_series.members, key=lambda item: item.ordinal):
            member_id = allocations.get(legacy_member.migration_identity)
            if member_id is None:
                _fail("invalid_member_id_allocation")
            account = accounts.get(legacy_member.account_id) if legacy_member.account_id is not None else None
            enabled = source_series.enabled and legacy_member.enabled and (account is None or account.enabled)
            output_members.append(
                _FleetSeriesMember(
                    member_id,
                    legacy_member.ordinal,
                    legacy_member.account_id,
                    enabled,
                    legacy_member.model_override,
                    legacy_member.skill_profile_override,
                    legacy_member.task_profile_override,
                )
            )
        output.append(
            _FleetSeriesV2(
                prefix,
                source_series.display_name,
                source_series.runner,
                source_series.provider,
                source_series.model,
                source_series.enabled,
                source_series.skill_profile,
                source_series.task_profile,
                tuple(output_members),
            )
        )

    winners = [item for item in plan.values() if item.disposition == "g_member"]
    winner_sources = [members[item.migration_identity][0] for item in winners]
    base = next(
        (item for item in snapshot.series if item.prefix == "g" and item.provider is _Provider.GEMINI_API),
        min(winner_sources, key=lambda item: item.prefix),
    )
    g_members: list[_FleetSeriesMember] = []
    for item in sorted(winners, key=lambda value: value.target_ordinal or 0):
        source_series, legacy_member = members[item.migration_identity]
        member_id = allocations.get(item.migration_identity)
        if member_id is None or item.target_ordinal is None:
            _fail("invalid_member_id_allocation")
        account = accounts.get(item.account_id)
        if account is None:
            _fail("invalid_migration_materialization")
        g_members.append(
            _FleetSeriesMember(
                member_id,
                item.target_ordinal,
                item.account_id,
                source_series.enabled and legacy_member.enabled and account.enabled,
                _override(legacy_member.model_override, source_series.model, base.model),
                _override(legacy_member.skill_profile_override, source_series.skill_profile, base.skill_profile),
                _override(legacy_member.task_profile_override, source_series.task_profile, base.task_profile),
            )
        )
    output.append(
        _FleetSeriesV2(
            "g",
            base.display_name,
            base.runner,
            base.provider,
            base.model,
            any(item.enabled for item in g_members),
            base.skill_profile,
            base.task_profile,
            tuple(g_members),
        )
    )
    return tuple(output)


def _allocation_by_identity(
    allocations: object,
    final_identities: tuple[str, ...],
) -> dict[str, str]:
    entries = _allocation_entries(allocations, code="invalid_member_id_allocation")
    expected = set(final_identities)
    if len(entries) != len(expected) or {identity for identity, _member_id in entries} != expected:
        _fail("invalid_member_id_allocation")
    result: dict[str, str] = {}
    used: set[str] = set()
    for identity, member_id in entries:
        if identity in result:
            _fail("invalid_member_id_allocation")
        canonical = _canonical_uuid4(member_id)
        if canonical is None or canonical in used:
            _fail("invalid_member_id_allocation")
        result[identity] = canonical
        used.add(canonical)
    return result


def materialize_g_series_v2(
    snapshot: _FleetMigrationSnapshot,
    plan: _GSeriesMigrationPlan,
    *,
    credential_bindings: _Mapping[str, str],
    allocations: _Collection[MemberIdAllocation],
) -> _FleetSnapshotV2:
    try:
        accounts, members = _validate_snapshot_shape(snapshot)
        validated_plan = _validate_plan(snapshot, plan, members)
        bindings = _binding_by_account(snapshot, credential_bindings)
        duplicate_losers = _duplicate_loser_accounts(snapshot, members, validated_plan, bindings)
        _validate_provider_references(accounts, members)
        final_identities = _final_identities(members, validated_plan)
        allocation_by_identity = _allocation_by_identity(allocations, final_identities)
        materialized_accounts = _materialize_accounts(snapshot, bindings, duplicate_losers)
        accounts_by_id = {account.account_id: account for account in materialized_accounts}
        materialized_series = _materialize_series(
            snapshot,
            members,
            validated_plan,
            allocation_by_identity,
            accounts_by_id,
        )
        candidate = _FleetSnapshotV2(2, snapshot.generation + 1, materialized_accounts, materialized_series)
        normalized = _normalize_fleet_document(_fleet_document(candidate))
        if type(normalized) is not _FleetSnapshotV2:
            _fail("invalid_migration_materialization")
        return normalized
    except GMigrationMaterializationError:
        raise
    except Exception:
        raise GMigrationMaterializationError("invalid_migration_materialization") from None
