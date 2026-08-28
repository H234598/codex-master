"""Pure, offline preparation for one fleet Registry V1 to V2 migration."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from hashlib import sha256
import json
import re

from .codex_usage_credential_authority import ProfileCredentialBinding
from .fleet_registry import (
    AuthKind,
    FleetAccountV2,
    FleetRuntimePrincipalV2,
    FleetSnapshot,
    FleetSnapshotV2,
    MAX_GENERATION,
    Provider,
    fleet_document,
    normalize_fleet_document,
)


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z", re.ASCII)
_PREPARED_CAPABILITY_SEAL = object()
_RECOVERY_CAPABILITY_SEAL = object()


class RegistryV2MigrationError(ValueError):
    """Sparse failure from the offline Registry V2 migration boundary."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class RegistryV2QuiescenceEvidence:
    source_generation: int
    source_digest: str
    runtime_broker_epoch: int
    stopped: bool
    active_principals_or_agents: int
    active_leases_or_reservations: int
    pending_registry_or_broker_transactions: int
    pending_recoveries: int

    def __repr__(self) -> str:
        return "RegistryV2QuiescenceEvidence(<redacted>)"

    def __str__(self) -> str:
        return repr(self)


@dataclass(frozen=True, slots=True, init=False)
class PreparedFleetRegistryV2Migration:
    source: FleetSnapshot
    candidate: FleetSnapshotV2
    source_digest: str
    candidate_digest: str
    quiescence_before: RegistryV2QuiescenceEvidence
    quiescence_after: RegistryV2QuiescenceEvidence
    profile_bindings: tuple[tuple[str, ProfileCredentialBinding], ...]
    _seal: object = field(init=False, repr=False, compare=False)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("prepared_capability_factory_required")

    def __repr__(self) -> str:
        return "PreparedFleetRegistryV2Migration(<redacted>)"

    def __str__(self) -> str:
        return repr(self)

    def __reduce_ex__(self, _protocol: int) -> object:
        raise TypeError("prepared_capability_not_serializable")

    def __copy__(self) -> PreparedFleetRegistryV2Migration:
        raise TypeError("prepared_capability_not_cloneable")

    def __deepcopy__(self, _memo: object) -> PreparedFleetRegistryV2Migration:
        raise TypeError("prepared_capability_not_cloneable")


@dataclass(frozen=True, slots=True, init=False)
class FleetRegistryV1RecoveryPlan:
    prepared: PreparedFleetRegistryV2Migration
    candidate: FleetSnapshot
    observed_candidate_digest: str
    quiescence_before: RegistryV2QuiescenceEvidence
    quiescence_after: RegistryV2QuiescenceEvidence
    _seal: object = field(init=False, repr=False, compare=False)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("recovery_capability_factory_required")

    def __repr__(self) -> str:
        return "FleetRegistryV1RecoveryPlan(<redacted>)"

    def __str__(self) -> str:
        return repr(self)

    def __reduce_ex__(self, _protocol: int) -> object:
        raise TypeError("recovery_capability_not_serializable")

    def __copy__(self) -> FleetRegistryV1RecoveryPlan:
        raise TypeError("recovery_capability_not_cloneable")

    def __deepcopy__(self, _memo: object) -> FleetRegistryV1RecoveryPlan:
        raise TypeError("recovery_capability_not_cloneable")


def _new_prepared(
    *,
    source: FleetSnapshot,
    candidate: FleetSnapshotV2,
    source_digest: str,
    candidate_digest: str,
    quiescence_before: RegistryV2QuiescenceEvidence,
    quiescence_after: RegistryV2QuiescenceEvidence,
    profile_bindings: tuple[tuple[str, ProfileCredentialBinding], ...],
) -> PreparedFleetRegistryV2Migration:
    prepared = object.__new__(PreparedFleetRegistryV2Migration)
    object.__setattr__(prepared, "source", source)
    object.__setattr__(prepared, "candidate", candidate)
    object.__setattr__(prepared, "source_digest", source_digest)
    object.__setattr__(prepared, "candidate_digest", candidate_digest)
    object.__setattr__(prepared, "quiescence_before", quiescence_before)
    object.__setattr__(prepared, "quiescence_after", quiescence_after)
    object.__setattr__(prepared, "profile_bindings", profile_bindings)
    object.__setattr__(prepared, "_seal", _PREPARED_CAPABILITY_SEAL)
    return prepared


def _new_recovery_plan(
    *,
    prepared: PreparedFleetRegistryV2Migration,
    candidate: FleetSnapshot,
    observed_candidate_digest: str,
    quiescence_before: RegistryV2QuiescenceEvidence,
    quiescence_after: RegistryV2QuiescenceEvidence,
) -> FleetRegistryV1RecoveryPlan:
    plan = object.__new__(FleetRegistryV1RecoveryPlan)
    object.__setattr__(plan, "prepared", prepared)
    object.__setattr__(plan, "candidate", candidate)
    object.__setattr__(plan, "observed_candidate_digest", observed_candidate_digest)
    object.__setattr__(plan, "quiescence_before", quiescence_before)
    object.__setattr__(plan, "quiescence_after", quiescence_after)
    object.__setattr__(plan, "_seal", _RECOVERY_CAPABILITY_SEAL)
    return plan


def _fail(code: str) -> None:
    raise RegistryV2MigrationError(code) from None


def _canonical_bytes(snapshot: FleetSnapshot | FleetSnapshotV2) -> bytes:
    return json.dumps(
        fleet_document(snapshot),
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _digest(payload: bytes) -> str:
    return "sha256:" + sha256(payload).hexdigest()


def _validated_source(source: object, expected_generation: object) -> FleetSnapshot:
    if type(source) is not FleetSnapshot:
        _fail("invalid_source")
    if type(expected_generation) is not int or source.generation != expected_generation:
        _fail("source_generation_conflict")
    if source.generation >= MAX_GENERATION:
        _fail("source_generation_overflow")
    try:
        normalized = normalize_fleet_document(fleet_document(source))
    except Exception:
        _fail("invalid_source")
    if type(normalized) is not FleetSnapshot or normalized != source:
        _fail("invalid_source")
    return source


def _validated_evidence(
    evidence: object,
    *,
    source_generation: int,
    source_digest: str,
) -> RegistryV2QuiescenceEvidence:
    if type(evidence) is not RegistryV2QuiescenceEvidence:
        _fail("quiescence_evidence_invalid")
    counters = (
        evidence.active_principals_or_agents,
        evidence.active_leases_or_reservations,
        evidence.pending_registry_or_broker_transactions,
        evidence.pending_recoveries,
    )
    if (
        type(evidence.source_generation) is not int
        or type(evidence.source_digest) is not str
        or _DIGEST.fullmatch(evidence.source_digest) is None
        or type(evidence.runtime_broker_epoch) is not int
        or evidence.runtime_broker_epoch < 0
        or type(evidence.stopped) is not bool
        or any(type(value) is not int or value < 0 for value in counters)
    ):
        _fail("quiescence_evidence_invalid")
    if (
        evidence.source_generation != source_generation
        or evidence.source_digest != source_digest
    ):
        _fail("quiescence_source_mismatch")
    if evidence.stopped is not True or any(counters):
        _fail("quiescence_activity")
    return evidence


def _observe(
    probe: object,
    *,
    source_generation: int,
    source_digest: str,
) -> RegistryV2QuiescenceEvidence:
    if not callable(probe):
        _fail("quiescence_probe_failed")
    try:
        evidence = probe()
    except Exception:
        _fail("quiescence_probe_failed")
    return _validated_evidence(
        evidence,
        source_generation=source_generation,
        source_digest=source_digest,
    )


def _copy_profile_bindings(
    profile_bindings: object,
) -> dict[str, ProfileCredentialBinding]:
    if not isinstance(profile_bindings, Mapping):
        _fail("invalid_migration_binding")
    try:
        supplied = dict(profile_bindings.items())
    except Exception:
        _fail("invalid_migration_binding")
    if any(
        type(account_id) is not str or type(binding) is not ProfileCredentialBinding
        for account_id, binding in supplied.items()
    ):
        _fail("invalid_migration_binding")
    return {
        account_id: ProfileCredentialBinding(binding.profile_id, binding.binding_id)
        for account_id, binding in supplied.items()
    }


def _materialize_candidate(
    source: FleetSnapshot,
    profile_bindings: object,
    runtime_principals: object,
) -> FleetSnapshotV2:
    if (
        not isinstance(profile_bindings, Mapping)
        or type(runtime_principals) is not tuple
    ):
        _fail("invalid_migration_binding")
    try:
        bindings = dict(profile_bindings.items())
    except Exception:
        _fail("invalid_migration_binding")
    if any(type(key) is not str for key in bindings):
        _fail("invalid_migration_binding")
    openai_account_ids = {
        account.account_id
        for account in source.accounts
        if account.provider is Provider.OPENAI_CHATGPT
    }
    if set(bindings) != openai_account_ids:
        _fail("invalid_migration_binding")
    principals_by_account: dict[str, FleetRuntimePrincipalV2] = {}
    principal_ids: set[str] = set()
    for principal in runtime_principals:
        if type(principal) is not FleetRuntimePrincipalV2:
            _fail("invalid_runtime_principal")
        if (
            principal.account_id in principals_by_account
            or principal.principal_id in principal_ids
        ):
            _fail("invalid_runtime_principal")
        principals_by_account[principal.account_id] = principal
        principal_ids.add(principal.principal_id)
    if set(principals_by_account) != openai_account_ids:
        _fail("invalid_runtime_principal")

    candidate_accounts: list[FleetAccountV2] = []
    for account in source.accounts:
        binding_id = None
        if account.account_id in openai_account_ids:
            binding = bindings[account.account_id]
            principal = principals_by_account[account.account_id]
            if (
                type(binding) is not ProfileCredentialBinding
                or account.auth_kind is not AuthKind.CHATGPT_SESSION
                or principal.account_id != account.account_id
                or principal.profile_id != binding.profile_id
                or principal.credential_binding_id != binding.binding_id
            ):
                _fail("invalid_migration_binding")
            binding_id = binding.binding_id
        candidate_accounts.append(
            FleetAccountV2(
                account_id=account.account_id,
                label=account.label,
                provider=account.provider,
                auth_kind=account.auth_kind,
                secret_state=account.secret_state,
                limit_state=account.limit_state,
                enabled=account.enabled,
                reset_at_utc=account.reset_at_utc,
                last_probe_at_utc=account.last_probe_at_utc,
                limit_reason=account.limit_reason,
                billing_group=account.billing_group,
                credential_binding_id=binding_id,
            )
        )
    active_bindings = [
        account.credential_binding_id
        for account in candidate_accounts
        if account.enabled and account.credential_binding_id is not None
    ]
    if len(active_bindings) != len(set(active_bindings)):
        _fail("duplicate_credential_binding")
    try:
        candidate = normalize_fleet_document(
            fleet_document(
                FleetSnapshotV2(
                    schema_version=2,
                    generation=source.generation + 1,
                    accounts=tuple(candidate_accounts),
                    series=(),
                    runtime_principals=runtime_principals,
                )
            )
        )
    except Exception:
        _fail("invalid_runtime_principal")
    if type(candidate) is not FleetSnapshotV2:
        _fail("invalid_runtime_principal")
    return candidate


def prepare_fleet_registry_v2_migration(
    source: object,
    *,
    expected_generation: object,
    profile_bindings: object,
    runtime_principals: object,
    quiescence_probe: Callable[[], RegistryV2QuiescenceEvidence],
) -> PreparedFleetRegistryV2Migration:
    """Prepare, but never write, one exact V1 to pool-only V2 transition."""

    validated_source = _validated_source(source, expected_generation)
    source_payload = _canonical_bytes(validated_source)
    source_digest = _digest(source_payload)
    before = _observe(
        quiescence_probe,
        source_generation=validated_source.generation,
        source_digest=source_digest,
    )
    copied_bindings = _copy_profile_bindings(profile_bindings)
    candidate = _materialize_candidate(
        validated_source, copied_bindings, runtime_principals
    )
    candidate_digest = _digest(_canonical_bytes(candidate))
    after = _observe(
        quiescence_probe,
        source_generation=validated_source.generation,
        source_digest=source_digest,
    )
    if after != before:
        _fail("quiescence_drift")
    return _new_prepared(
        source=validated_source,
        candidate=candidate,
        source_digest=source_digest,
        candidate_digest=candidate_digest,
        quiescence_before=before,
        quiescence_after=after,
        profile_bindings=tuple(sorted(copied_bindings.items())),
    )


def _validated_prepared(
    prepared: object,
) -> tuple[PreparedFleetRegistryV2Migration, bytes]:
    if (
        type(prepared) is not PreparedFleetRegistryV2Migration
        or getattr(prepared, "_seal", None) is not _PREPARED_CAPABILITY_SEAL
    ):
        _fail("prepared_integrity_invalid")
    try:
        if type(prepared.profile_bindings) is not tuple:
            _fail("prepared_integrity_invalid")
        stored_bindings: dict[str, ProfileCredentialBinding] = {}
        previous_account_id: str | None = None
        for item in prepared.profile_bindings:
            if type(item) is not tuple or len(item) != 2:
                _fail("prepared_integrity_invalid")
            account_id, binding = item
            if (
                type(account_id) is not str
                or type(binding) is not ProfileCredentialBinding
                or (
                    previous_account_id is not None
                    and account_id <= previous_account_id
                )
            ):
                _fail("prepared_integrity_invalid")
            stored_bindings[account_id] = binding
            previous_account_id = account_id
        rematerialized_candidate = _materialize_candidate(
            prepared.source,
            stored_bindings,
            prepared.candidate.runtime_principals,
        )
        if rematerialized_candidate != prepared.candidate:
            _fail("prepared_integrity_invalid")
        source_payload = _canonical_bytes(prepared.source)
        candidate_payload = _canonical_bytes(prepared.candidate)
        normalized_source = normalize_fleet_document(fleet_document(prepared.source))
        normalized_candidate = normalize_fleet_document(
            fleet_document(prepared.candidate)
        )
    except Exception:
        _fail("prepared_integrity_invalid")
    if (
        type(prepared.source) is not FleetSnapshot
        or type(prepared.candidate) is not FleetSnapshotV2
        or type(normalized_source) is not FleetSnapshot
        or type(normalized_candidate) is not FleetSnapshotV2
        or normalized_source != prepared.source
        or normalized_candidate != prepared.candidate
        or prepared.candidate.generation != prepared.source.generation + 1
        or prepared.source_digest != _digest(source_payload)
        or prepared.candidate_digest != _digest(candidate_payload)
    ):
        _fail("prepared_integrity_invalid")
    try:
        before = _validated_evidence(
            prepared.quiescence_before,
            source_generation=prepared.source.generation,
            source_digest=prepared.source_digest,
        )
        after = _validated_evidence(
            prepared.quiescence_after,
            source_generation=prepared.source.generation,
            source_digest=prepared.source_digest,
        )
    except RegistryV2MigrationError:
        _fail("prepared_integrity_invalid")
    if before != after:
        _fail("prepared_integrity_invalid")
    return prepared, candidate_payload


def plan_fleet_registry_v1_recovery(
    prepared: object,
    observed_candidate: object,
    *,
    observed_candidate_digest: object,
    quiescence_probe: Callable[[], RegistryV2QuiescenceEvidence],
) -> FleetRegistryV1RecoveryPlan:
    """Plan a monotonic V1 recovery without committing either registry state."""

    validated, candidate_payload = _validated_prepared(prepared)
    if type(observed_candidate) is not FleetSnapshotV2:
        _fail("recovery_candidate_mismatch")
    try:
        observed_payload = _canonical_bytes(observed_candidate)
        normalized_observed = normalize_fleet_document(
            fleet_document(observed_candidate)
        )
    except Exception:
        _fail("recovery_candidate_mismatch")
    if (
        type(observed_candidate_digest) is not str
        or _DIGEST.fullmatch(observed_candidate_digest) is None
        or type(normalized_observed) is not FleetSnapshotV2
        or normalized_observed != observed_candidate
        or observed_candidate.generation != validated.source.generation + 1
        or observed_payload != candidate_payload
        or observed_candidate_digest != validated.candidate_digest
        or observed_candidate_digest != _digest(observed_payload)
    ):
        _fail("recovery_candidate_mismatch")
    if validated.source.generation > MAX_GENERATION - 2:
        _fail("recovery_generation_overflow")

    before = _observe(
        quiescence_probe,
        source_generation=validated.candidate.generation,
        source_digest=validated.candidate_digest,
    )
    try:
        candidate = normalize_fleet_document(
            fleet_document(
                FleetSnapshot(
                    schema_version=1,
                    generation=validated.source.generation + 2,
                    accounts=validated.source.accounts,
                    series=validated.source.series,
                )
            )
        )
    except Exception:
        _fail("recovery_candidate_invalid")
    if type(candidate) is not FleetSnapshot:
        _fail("recovery_candidate_invalid")
    after = _observe(
        quiescence_probe,
        source_generation=validated.candidate.generation,
        source_digest=validated.candidate_digest,
    )
    if after != before:
        _fail("quiescence_drift")
    return _new_recovery_plan(
        prepared=validated,
        candidate=candidate,
        observed_candidate_digest=observed_candidate_digest,
        quiescence_before=before,
        quiescence_after=after,
    )
