"""Authoritative local Hive runtime assembly.

The configuration loaders and individual authority/repository stores are
useful in isolation, but a productive admission path must use one coherent
set of those stores. This module assembles that set, verifies configuration
parity, and keeps principal materialization explicit. It does not select a
provider, start a process, or mutate a repository.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
import hmac
import os
from pathlib import Path
import re
import stat
from typing import Literal

from the_hive.hive.authority import AuthorityContext, AuthorityEngine
from the_hive.hive.config import (
    AgentClassCatalogSnapshot,
    AgentClassProfile,
    HiveConfig,
    HiveConfigError,
    _is_catalog_digest,
    load_agent_class_catalog_snapshot,
    load_agent_class_catalog_snapshot_bytes,
    load_hive_config,
    load_hive_config_bytes,
)
from the_hive.hive.events import HiveEventError, HiveEventStore
from the_hive.hive.principals import Principal, PrincipalRegistry
from the_hive.hive.repositories import RepositoryBinding, RepositoryRegistry
from the_hive.hive.state import HiveStateError, HiveStateStore
from the_hive.runtime_layout import (
    LayoutError,
    RuntimeLayout,
    validate_runtime_metadata,
)
from the_hive.agent_resolver import (
    LEADERSHIP_CLASS_IDS,
    REASONING_RANK,
    policies_from_catalogs,
    validate_canonical_agent_tuple,
)
from the_hive.selection.model_policy import (
    ModelPolicyRegistry,
    load_model_policy,
    load_model_policy_bytes,
)
from the_hive.usage_snapshot import (
    ModelInvocabilityV1,
    ModelInvocabilityProjectionV1,
    PoolAuthorityV2,
    UsageEvidenceV2,
    read_usage_evidence_v2,
)


class HiveRuntimeError(ValueError):
    """Raised when the authoritative local Hive bundle cannot be assembled."""


_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_RUNTIME_STATES = frozenset({"ready", "not_configured", "invalid", "unavailable"})
_PILOT_REPOSITORY = "codex-master"
_PILOT_QUEEN = "queen-codex-master"
_PILOT_REMOTE = "https://github.com/H234598/codex-master.git"
_PILOT_FEATURE_FLAGS = frozenset({"sp0_passive", "sp1_deadline", "sp2_secondary_model", "sp3_fairness"})
_GLOBAL_PILOT_REASON_CODES = frozenset(
    {
        "candidate_missing",
        "candidate_mapping_conflict",
        "model_capability_conflicting",
        "model_capability_invalid",
        "model_capability_missing",
        "model_capability_stale",
        "model_policy_invalid",
        "model_policy_mismatch",
        "model_uninvocable",
        "pilot_class_ambiguous",
        "pilot_class_invalid",
        "pool_authority_ambiguous",
        "pool_authority_missing",
        "pool_authority_unready",
        "usage_generation_missing",
        "usage_invalid",
        "usage_missing",
        "usage_partial",
        "usage_stale",
        "usage_unattested",
    }
)
_GLOBAL_PILOT_FRESHNESS = frozenset({"fresh", "stale", "unknown"})
_GLOBAL_PILOT_GENERATION_RE = re.compile(r"^[0-9a-f]{32}$")


@dataclass(frozen=True, slots=True)
class GlobalPilotReadinessV1:
    """A bounded, diagnostic-only projection of one verified V2 generation."""

    pilot: Literal["ready", "blocked"]
    generation_id: str | None
    freshness: Literal["fresh", "stale", "unknown"]
    candidate_count: int
    reason_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            self.pilot not in {"ready", "blocked"}
            or self.generation_id is not None
            and (
                not isinstance(self.generation_id, str)
                or _GLOBAL_PILOT_GENERATION_RE.fullmatch(self.generation_id) is None
            )
            or self.freshness not in _GLOBAL_PILOT_FRESHNESS
            or type(self.candidate_count) is not int
            or not 0 <= self.candidate_count <= 256
            or type(self.reason_codes) is not tuple
            or len(self.reason_codes) > 8
            or any(
                not isinstance(code, str) or code not in _GLOBAL_PILOT_REASON_CODES
                for code in self.reason_codes
            )
            or len(set(self.reason_codes)) != len(self.reason_codes)
        ):
            raise HiveRuntimeError("invalid_global_pilot_readiness")

    def public(self) -> dict[str, object]:
        """Return only generation/freshness/count/reason diagnostic fields."""

        return {
            "schema_version": 1,
            "pilot": self.pilot,
            "generation_id": self.generation_id,
            "freshness": self.freshness,
            "candidate_count": self.candidate_count,
            "reason_codes": list(self.reason_codes),
            "raw_output": "not_returned",
        }


@dataclass(frozen=True, slots=True)
class HiveRuntimeEvidence:
    """Bounded, read-only projection shared by Hive diagnostics."""

    schema_version: int
    mode: str
    config_digest: str | None
    catalog_digest: str | None
    repository: str
    principal: str
    authority: str
    state: str
    pilot: str
    reason_codes: tuple[str, ...]
    mutation_performed: bool = False
    repository_count: int = 0
    principal_count: int = 0
    global_pilot_readiness: GlobalPilotReadinessV1 | None = None

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise HiveRuntimeError("invalid_hive_runtime_evidence")
        if self.mode not in {"disabled", "shadow", "enforced"}:
            raise HiveRuntimeError("invalid_hive_runtime_evidence")
        for digest in (self.config_digest, self.catalog_digest):
            if digest is not None and not _DIGEST_RE.fullmatch(digest):
                raise HiveRuntimeError("invalid_hive_runtime_evidence")
        if self.repository not in _RUNTIME_STATES or self.principal not in _RUNTIME_STATES:
            raise HiveRuntimeError("invalid_hive_runtime_evidence")
        if self.state not in _RUNTIME_STATES or self.authority not in {"ready", "fail_closed"}:
            raise HiveRuntimeError("invalid_hive_runtime_evidence")
        if self.pilot not in {"ready", "blocked"}:
            raise HiveRuntimeError("invalid_hive_runtime_evidence")
        if (
            type(self.reason_codes) is not tuple
            or any(
                not isinstance(code, str)
                or not 1 <= len(code) <= 96
                or re.fullmatch(r"[a-z][a-z0-9_-]*", code) is None
                for code in self.reason_codes
            )
            or len(set(self.reason_codes)) != len(self.reason_codes)
        ):
            raise HiveRuntimeError("invalid_hive_runtime_evidence")
        if type(self.mutation_performed) is not bool:
            raise HiveRuntimeError("invalid_hive_runtime_evidence")
        if (
            type(self.repository_count) is not int
            or self.repository_count < 0
            or type(self.principal_count) is not int
            or self.principal_count < 0
        ):
            raise HiveRuntimeError("invalid_hive_runtime_evidence")
        if self.global_pilot_readiness is not None and not isinstance(
            self.global_pilot_readiness, GlobalPilotReadinessV1
        ):
            raise HiveRuntimeError("invalid_hive_runtime_evidence")

    @property
    def checks(self) -> dict[str, str]:
        return {
            "authority": self.authority,
            "repository": self.repository,
            "state": self.state,
        }

    def public(self) -> dict[str, object]:
        """Return only bounded status values; no roots, secrets, or raw output."""

        return {
            "schema_version": self.schema_version,
            "mode": self.mode,
            "config_digest": self.config_digest,
            "catalog_digest": self.catalog_digest,
            "repository": self.repository,
            "principal": self.principal,
            "authority": self.authority,
            "state": self.state,
            "pilot": self.pilot,
            "reason_codes": list(self.reason_codes),
            "mutation_performed": self.mutation_performed,
            "raw_output": "not_returned",
        }


def _default_repository_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _default_hive_state_root() -> Path:
    root = os.environ.get("CODEX_MASTER_MCP_STATE") or os.environ.get("CODEX_AGENT_MCP_STATE")
    return (Path(root).expanduser() if root else Path("~/.local/state/codex-master-mcp").expanduser()) / "hive"


def _bounded_reason(code: str) -> str:
    return code if re.fullmatch(r"[a-z][a-z0-9_-]{0,95}", code) else "hive_runtime_unavailable"


def _pool_evidence_now(clock: Callable[[], datetime] | None) -> datetime | None:
    try:
        value = (clock or (lambda: datetime.now(UTC)))()
    except Exception:
        return None
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta():
        return None
    return value.astimezone(UTC)


def _global_pilot_readiness(
    *,
    pilot: Literal["ready", "blocked"],
    generation_id: str | None,
    freshness: Literal["fresh", "stale", "unknown"],
    candidate_count: int = 0,
    reason_codes: tuple[str, ...] = (),
) -> GlobalPilotReadinessV1:
    return GlobalPilotReadinessV1(
        pilot,
        generation_id,
        freshness,
        candidate_count,
        tuple(dict.fromkeys(reason_codes)),
    )


def _unknown_global_pilot_readiness(reason: str = "usage_missing") -> GlobalPilotReadinessV1:
    if reason not in _GLOBAL_PILOT_REASON_CODES:
        reason = "usage_invalid"
    return _global_pilot_readiness(
        pilot="blocked", generation_id=None, freshness="unknown", reason_codes=(reason,)
    )


def _pilot_class_id(
    config: HiveConfig, classes: Mapping[str, AgentClassProfile]
) -> str | None:
    configured = tuple(
        raw.get("class_id")
        for raw in config.principals
        if isinstance(raw, Mapping)
        and raw.get("repo_id") is not None
        and isinstance(raw.get("class_id"), str)
    )
    if len(configured) != 1:
        return None
    class_id = configured[0]
    if class_id not in classes or class_id not in LEADERSHIP_CLASS_IDS:
        return None
    return class_id


def _global_pilot_readiness_for_reader_fields(
    *,
    status: object,
    captured_at: object,
    generated_at: object,
    pool_authorities: object,
    model_invocability: object,
    generation_id: object,
    config: HiveConfig,
    classes: Mapping[str, AgentClassProfile],
    model_registry: ModelPolicyRegistry,
    now: Callable[[], datetime] | None,
) -> GlobalPilotReadinessV1:
    """Project fields extracted only after the controlled V2 reader return."""

    if (
        not isinstance(generation_id, str)
        or _GLOBAL_PILOT_GENERATION_RE.fullmatch(generation_id) is None
    ):
        return _global_pilot_readiness(
            pilot="blocked",
            generation_id=None,
            freshness="unknown",
            reason_codes=("usage_generation_missing",),
        )
    if type(status) is not str:
        return _global_pilot_readiness(
            pilot="blocked",
            generation_id=generation_id,
            freshness="unknown",
            reason_codes=("usage_invalid",),
        )
    if status != "complete":
        reason = {
            "partial": "usage_partial",
            "stale": "usage_stale",
            "unavailable": "usage_missing",
            "busy": "usage_missing",
            "invalid": "usage_invalid",
        }.get(status, "usage_invalid")
        return _global_pilot_readiness(
            pilot="blocked",
            generation_id=generation_id,
            freshness="stale" if status == "stale" else "unknown",
            reason_codes=(reason,),
        )
    if captured_at is None or generated_at is None:
        return _global_pilot_readiness(
            pilot="blocked",
            generation_id=generation_id,
            freshness="unknown",
            reason_codes=("usage_missing",),
        )
    observed_now = _pool_evidence_now(now)
    if observed_now is None or generated_at > observed_now:
        return _global_pilot_readiness(
            pilot="blocked",
            generation_id=generation_id,
            freshness="unknown",
            reason_codes=("usage_invalid",),
        )

    if not isinstance(config, HiveConfig) or config.mode != "enforced":
        return _global_pilot_readiness(
            pilot="blocked",
            generation_id=generation_id,
            freshness="fresh",
            reason_codes=("pilot_class_invalid",),
        )
    if not isinstance(classes, Mapping) or any(
        type(value) is not AgentClassProfile for value in classes.values()
    ) or type(model_registry) is not ModelPolicyRegistry:
        return _global_pilot_readiness(
            pilot="blocked",
            generation_id=generation_id,
            freshness="fresh",
            reason_codes=("model_policy_invalid",),
        )
    class_id = _pilot_class_id(config, classes)
    if class_id is None:
        return _global_pilot_readiness(
            pilot="blocked",
            generation_id=generation_id,
            freshness="fresh",
            reason_codes=("pilot_class_ambiguous",),
        )
    try:
        class_policies, model_policies = policies_from_catalogs(classes, model_registry)
    except Exception:
        return _global_pilot_readiness(
            pilot="blocked",
            generation_id=generation_id,
            freshness="fresh",
            reason_codes=("model_policy_invalid",),
        )
    class_policy = next(
        (item for item in class_policies if item.class_id == class_id), None
    )
    if (
        class_policy is None
        or class_policy.default_lifecycle != "persistent"
        or class_policy.allowed_lifecycles != ("persistent",)
    ):
        return _global_pilot_readiness(
            pilot="blocked",
            generation_id=generation_id,
            freshness="fresh",
            reason_codes=("pilot_class_invalid",),
        )

    authorities = pool_authorities
    if type(authorities) is not tuple or any(
        type(authority) is not PoolAuthorityV2 for authority in authorities
    ):
        return _global_pilot_readiness(
            pilot="blocked",
            generation_id=generation_id,
            freshness="fresh",
            reason_codes=("pool_authority_missing",),
        )
    authority_keys = tuple(
        (item.account_id, item.pool_id, item.provider) for item in authorities
    )
    if len(set(authority_keys)) != len(authority_keys):
        return _global_pilot_readiness(
            pilot="blocked",
            generation_id=generation_id,
            freshness="fresh",
            reason_codes=("pool_authority_ambiguous",),
        )
    if not authorities:
        return _global_pilot_readiness(
            pilot="blocked",
            generation_id=generation_id,
            freshness="fresh",
            reason_codes=("pool_authority_missing",),
        )

    projection = model_invocability
    if not isinstance(projection, ModelInvocabilityProjectionV1):
        return _global_pilot_readiness(
            pilot="blocked",
            generation_id=generation_id,
            freshness="fresh",
            reason_codes=("model_capability_missing",),
        )
    if projection.status == "unattested":
        return _global_pilot_readiness(
            pilot="blocked",
            generation_id=generation_id,
            freshness="fresh",
            reason_codes=("model_capability_missing",),
        )
    if projection.status == "stale":
        return _global_pilot_readiness(
            pilot="blocked",
            generation_id=generation_id,
            freshness="stale",
            reason_codes=("model_capability_stale",),
        )
    if projection.status != "complete" or type(projection.capabilities) is not tuple:
        return _global_pilot_readiness(
            pilot="blocked",
            generation_id=generation_id,
            freshness="fresh",
            reason_codes=("model_capability_invalid",),
        )
    if any(type(item) is not ModelInvocabilityV1 for item in projection.capabilities):
        return _global_pilot_readiness(
            pilot="blocked",
            generation_id=generation_id,
            freshness="fresh",
            reason_codes=("model_capability_invalid",),
        )
    capability_keys = tuple(
        (item.account_id, item.model_id, item.runner_id)
        for item in projection.capabilities
    )
    if len(capability_keys) != len(set(capability_keys)):
        return _global_pilot_readiness(
            pilot="blocked",
            generation_id=generation_id,
            freshness="fresh",
            reason_codes=("model_capability_conflicting",),
        )
    if not projection.capabilities:
        return _global_pilot_readiness(
            pilot="blocked",
            generation_id=generation_id,
            freshness="fresh",
            reason_codes=("model_capability_missing",),
        )

    model_by_id = {item.model_id: item for item in model_policies}
    matched_mapping = False
    unready_pool = False
    uninvocable = False
    policy_mismatch = False
    candidates = 0
    for authority in authorities:
        if authority.hive_available is not True:
            unready_pool = True
            continue
        if (
            authority.persistent_leadership_eligible is not True
            or authority.long_running_leadership_eligible is not True
            or "persistent" not in authority.allowed_lifecycles
        ):
            unready_pool = True
            continue
        if (
            authority.reasoning_minimum not in REASONING_RANK
            or authority.reasoning_maximum not in REASONING_RANK
            or REASONING_RANK[authority.reasoning_minimum]
            > REASONING_RANK[authority.reasoning_maximum]
            or REASONING_RANK[authority.reasoning_minimum]
            > REASONING_RANK[class_policy.min_reasoning]
            or REASONING_RANK[authority.reasoning_maximum]
            < REASONING_RANK[class_policy.max_reasoning]
        ):
            policy_mismatch = True
            continue
        for capability in projection.capabilities:
            if capability.account_id != authority.account_id:
                continue
            matched_mapping = True
            model_policy = model_by_id.get(capability.model_id)
            definition = model_registry.get_exact(capability.model_id)
            if model_policy is None or definition is None or definition.provider != authority.provider:
                policy_mismatch = True
                continue
            if model_policy.family not in authority.allowed_model_families:
                policy_mismatch = True
                continue
            try:
                validate_canonical_agent_tuple(
                    class_policy,
                    model_policy,
                    "persistent",
                    class_policy.max_reasoning,
                )
            except ValueError:
                policy_mismatch = True
                continue
            if (
                capability.meter_visible is not True
                or capability.catalog_visible is not True
                or capability.supported_in_api is not True
            ):
                policy_mismatch = True
                continue
            if capability.runner_invocable is not True:
                uninvocable = True
                continue
            candidates += 1

    if candidates:
        return _global_pilot_readiness(
            pilot="ready",
            generation_id=generation_id,
            freshness="fresh",
            candidate_count=candidates,
        )
    reasons: list[str] = []
    if not matched_mapping:
        reasons.append("candidate_mapping_conflict")
    if unready_pool:
        reasons.append("pool_authority_unready")
    if uninvocable:
        reasons.append("model_uninvocable")
    if policy_mismatch:
        reasons.append("model_policy_mismatch")
    if not reasons:
        reasons.append("candidate_missing")
    return _global_pilot_readiness(
        pilot="blocked",
        generation_id=generation_id,
        freshness="fresh",
        reason_codes=tuple(reasons),
    )


def global_pilot_readiness_from_evidence(
    evidence: object,
    *,
    config: HiveConfig,
    classes: Mapping[str, AgentClassProfile],
    model_registry: ModelPolicyRegistry,
    now: Callable[[], datetime] | None = None,
) -> GlobalPilotReadinessV1:
    """Reject caller-supplied evidence; only the controlled reader path projects readiness."""

    del evidence, config, classes, model_registry, now
    return _unknown_global_pilot_readiness("usage_unattested")


def _read_global_pilot_readiness_for_config(
    *,
    config: HiveConfig,
    classes: Mapping[str, AgentClassProfile],
    model_registry: ModelPolicyRegistry,
    now: Callable[[], datetime] | None,
) -> GlobalPilotReadinessV1:
    observed_now = _pool_evidence_now(now)
    if observed_now is None:
        return _unknown_global_pilot_readiness("usage_invalid")
    reader_result = read_usage_evidence_v2(clock=lambda: observed_now)
    if type(reader_result) is not UsageEvidenceV2:
        return _unknown_global_pilot_readiness("usage_unattested")
    return _global_pilot_readiness_for_reader_fields(
        status=reader_result.status,
        captured_at=reader_result.captured_at,
        generated_at=reader_result.generated_at,
        pool_authorities=reader_result.pool_authorities,
        model_invocability=reader_result.model_invocability,
        generation_id=reader_result.generation_id,
        config=config,
        classes=classes,
        model_registry=model_registry,
        now=lambda: observed_now,
    )


def read_global_pilot_readiness(
    *, now: Callable[[], datetime] | None = None
) -> GlobalPilotReadinessV1:
    """Read the canonical runtime configuration and the real V2 reader once."""

    try:
        layout = RuntimeLayout.from_module_path(Path(__file__))
        classes_snapshot = load_agent_class_catalog_snapshot_bytes(
            layout.read_attested_file("codex-agent-classes.json")
        )
        config = load_hive_config_bytes(
            layout.read_attested_file("codex-hive.json"), classes_snapshot.classes
        )
        model_registry = load_model_policy_bytes(
            layout.read_attested_file("codex-model-policy.json")
        )
    except (HiveConfigError, LayoutError, OSError, TypeError, ValueError):
        return _unknown_global_pilot_readiness("model_policy_invalid")
    return _read_global_pilot_readiness_for_config(
        config=config,
        classes=classes_snapshot.classes,
        model_registry=model_registry,
        now=now,
    )


def enforced_pilot_gate(
    config: HiveConfig,
    classes: Mapping[str, AgentClassProfile],
    supplied_pool_attestation: object | None = None,
    *,
    now: Callable[[], datetime] | None = None,
) -> dict[str, object]:
    """Block static Pilot/Hive authority until an immutable request binding exists."""

    if not isinstance(config, HiveConfig) or not isinstance(classes, Mapping):
        return {"allowed": False, "reason_code": "pilot_config_invalid", "raw_output": "not_returned"}
    repositories = tuple(config.repositories)
    principals = tuple(config.principals)
    repository_ok = (
        config.mode == "enforced"
        and len(repositories) == 1
        and repositories[0].get("repo_id") == _PILOT_REPOSITORY
        and repositories[0].get("remote_identity") == _PILOT_REMOTE
        and repositories[0].get("default_branch") == "main"
        and isinstance(repositories[0].get("config_digest"), str)
        and _DIGEST_RE.fullmatch(repositories[0]["config_digest"]) is not None
    )
    principal_rows = {
        row.get("principal_id"): row
        for row in principals
        if isinstance(row, Mapping)
    }
    principals_ok = (
        set(principal_rows) == {"godbee-main", _PILOT_QUEEN}
        and principal_rows.get("godbee-main", {}).get("class_id") == "gottbiene"
        and principal_rows.get("godbee-main", {}).get("parent_principal_id") is None
        and principal_rows.get("godbee-main", {}).get("repo_id") is None
        and principal_rows.get(_PILOT_QUEEN, {}).get("class_id") == "koenigin"
        and principal_rows.get(_PILOT_QUEEN, {}).get("parent_principal_id") == "godbee-main"
        and principal_rows.get(_PILOT_QUEEN, {}).get("repo_id") == _PILOT_REPOSITORY
    )
    flags_ok = (
        set(config.feature_flags) == _PILOT_FEATURE_FLAGS
        and all(value is False for value in config.feature_flags.values())
    )
    queen = classes.get("koenigin")
    queen_ok = (
        isinstance(queen, AgentClassProfile)
        and queen.allowed_model_families == ("sol",)
        and queen.min_reasoning == "max"
        and queen.max_reasoning == "max"
        and queen.public_lifecycle == "persistent"
        and queen.allowed_lifecycles == ("persistent",)
    )
    structural_ok = repository_ok and principals_ok and flags_ok and queen_ok
    if not structural_ok:
        return {"allowed": False, "reason_code": "pilot_config_invalid", "raw_output": "not_returned"}
    if supplied_pool_attestation is not None:
        return {"allowed": False, "reason_code": "pilot_account_attestation_invalid", "raw_output": "not_returned"}
    observed_now = _pool_evidence_now(now)
    if observed_now is None:
        return {"allowed": False, "reason_code": "pilot_account_attestation_missing", "raw_output": "not_returned"}
    return {
        "allowed": False,
        "reason_code": "pilot_account_attestation_invalid",
        "raw_output": "not_returned",
    }


def _existing_state_kind(path: Path) -> str:
    try:
        current = path.lstat()
    except FileNotFoundError:
        return "not_configured"
    except OSError:
        return "unavailable"
    if stat.S_ISLNK(current.st_mode) or not stat.S_ISDIR(current.st_mode):
        return "invalid"
    if current.st_uid != os.geteuid() or stat.S_IMODE(current.st_mode) != 0o700:
        return "invalid"
    try:
        lock = (path / ".hive-state.lock").lstat()
    except FileNotFoundError:
        return "unavailable"
    except OSError:
        return "unavailable"
    if (
        stat.S_ISLNK(lock.st_mode)
        or not stat.S_ISREG(lock.st_mode)
        or lock.st_nlink != 1
        or lock.st_uid != os.geteuid()
        or stat.S_IMODE(lock.st_mode) != 0o600
    ):
        return "invalid"
    return "ready"


def _validate_runtime_image_repository_evidence(
    layout: RuntimeLayout, config: HiveConfig
) -> None:
    """Prove that configured logical repositories belong to one image generation.

    This intentionally offers no root capability: all configuration bytes were
    read through ``layout.read_attested_file()``, and the final revalidation
    pins them to that same immutable image generation.
    """

    if not isinstance(layout, RuntimeLayout) or not isinstance(config, HiveConfig):
        raise HiveRuntimeError("invalid_runtime_image_evidence")
    for repository in config.repositories:
        if not isinstance(repository, Mapping) or not isinstance(repository.get("repo_id"), str):
            raise HiveRuntimeError("invalid_runtime_image_evidence")
    validate_runtime_metadata(layout)


def _verify_runtime_image_principal_evidence(
    config: HiveConfig,
    classes: Mapping[str, AgentClassProfile],
    state_root: Path,
) -> None:
    """Read state/principal parity without constructing runtime authority."""

    state = HiveStateStore(state_root, read_only=True)
    principals = PrincipalRegistry(state)
    _verify_principal_parity(principals, _expected_principals(config, classes))
    capabilities: dict[str, frozenset[str]] = {}
    for profile in classes.values():
        current = frozenset(profile.capabilities)
        previous = capabilities.get(profile.authority_profile)
        if previous is not None and previous != current:
            raise HiveRuntimeError("authority_profile_capability_conflict")
        capabilities[profile.authority_profile] = current


def read_hive_runtime_evidence(
    *,
    catalog_path: Path | None = None,
    config_path: Path | None = None,
    state_root: Path | None = None,
    repository_roots: Mapping[str, Path] | None = None,
    dynamic_account_evidence: object | None = None,
    now: Callable[[], datetime] | None = None,
) -> HiveRuntimeEvidence:
    """Read one canonical Hive projection without creating or repairing state."""

    use_runtime_image = (
        catalog_path is None and config_path is None and repository_roots is None
    )
    state_root = state_root or _default_hive_state_root()
    if not use_runtime_image:
        repository_root = _default_repository_root()
        catalog_path = catalog_path or repository_root / "codex-agent-classes.json"
        config_path = config_path or repository_root / "codex-hive.json"
    empty = {
        "schema_version": 1,
        "mode": "disabled",
        "config_digest": None,
        "catalog_digest": None,
        "repository": "unavailable",
        "principal": "unavailable",
        "authority": "fail_closed",
        "state": "unavailable",
        "pilot": "blocked",
        "reason_codes": (),
        "repository_count": 0,
        "principal_count": 0,
    }
    if (
        not isinstance(state_root, Path)
        or not state_root.is_absolute()
        or (
            not use_runtime_image
            and (
                not isinstance(catalog_path, Path)
                or not catalog_path.is_absolute()
                or not isinstance(config_path, Path)
                or not config_path.is_absolute()
            )
        )
    ):
        return HiveRuntimeEvidence(
            **{**empty, "reason_codes": ("hive_runtime_unavailable",)}
        )
    try:
        model_registry: ModelPolicyRegistry
        if use_runtime_image:
            layout = RuntimeLayout.from_module_path(Path(__file__))
            snapshot = load_agent_class_catalog_snapshot_bytes(
                layout.read_attested_file("codex-agent-classes.json")
            )
            config = load_hive_config_bytes(
                layout.read_attested_file("codex-hive.json"), snapshot.classes
            )
            _validate_runtime_image_repository_evidence(layout, config)
            model_registry = load_model_policy_bytes(
                layout.read_attested_file("codex-model-policy.json")
            )
        else:
            assert isinstance(catalog_path, Path) and isinstance(config_path, Path)
            snapshot = load_agent_class_catalog_snapshot(catalog_path)
            config = load_hive_config(config_path, snapshot.classes)
            model_registry = load_model_policy(
                _default_repository_root() / "codex-model-policy.json"
            )
    except (HiveConfigError, LayoutError, OSError, TypeError, ValueError):
        return HiveRuntimeEvidence(
            **{**empty, "reason_codes": ("hive_config_unavailable",)}
        )

    if dynamic_account_evidence is not None:
        global_pilot_readiness = _unknown_global_pilot_readiness("usage_unattested")
    else:
        global_pilot_readiness = _read_global_pilot_readiness_for_config(
            config=config,
            classes=snapshot.classes,
            model_registry=model_registry,
            now=now,
        )

    state_kind = _existing_state_kind(state_root)
    repository_kind = "not_configured" if not config.repositories else "unavailable"
    principal_kind = "not_configured" if not config.principals else (
        "not_configured" if state_kind == "not_configured" else state_kind
    )
    reasons: list[str] = []
    if not config.repositories:
        reasons.append("repository_not_configured")
    elif not use_runtime_image and repository_roots is None:
        reasons.append("repository_root_unavailable")
    if not config.principals:
        reasons.append("principal_not_configured")
    if state_kind == "not_configured":
        reasons.append("state_not_configured")
    elif state_kind != "ready":
        reasons.append("state_unavailable" if state_kind == "unavailable" else "state_invalid")

    if config.repositories and use_runtime_image:
        repository_kind = "ready"
    elif config.repositories and repository_roots is not None:
        try:
            repositories = _build_repositories(config, dict(repository_roots))
            for binding in config.repositories:
                validation = repositories.validate(binding["repo_id"])
                if not validation.allowed:
                    raise HiveRuntimeError("hive_repository_invalid")
            repository_kind = "ready"
        except (HiveRuntimeError, OSError, TypeError, ValueError):
            repository_kind = "invalid"
            reasons.append("repository_invalid")

    diagnostics_ready = False
    if state_kind == "ready" and repository_kind == "ready" and config.principals:
        try:
            if use_runtime_image:
                _verify_runtime_image_principal_evidence(
                    config, snapshot.classes, state_root
                )
            else:
                build_hive_runtime(
                    config,
                    snapshot.classes,
                    repository_roots=dict(repository_roots or {}),
                    state_root=state_root,
                    materialize_principals=False,
                    now=now,
                    read_only=True,
                )
            diagnostics_ready = True
        except (HiveRuntimeError, HiveStateError, HiveEventError, OSError, TypeError, ValueError):
            reasons.append("hive_runtime_invalid")
            principal_kind = "invalid"

    if diagnostics_ready:
        repository_kind = "ready"
        principal_kind = "ready"
        state_kind = "ready"
        repository_count = len(config.repositories)
        principal_count = len(config.principals)
    else:
        repository_count = len(config.repositories)
        principal_count = len(config.principals) if state_kind == "ready" and config.principals else 0
    reasons = list(dict.fromkeys(reasons))
    if dynamic_account_evidence is not None:
        enforced_pilot_gate(
            config,
            snapshot.classes,
            dynamic_account_evidence,
            now=now,
        )
    # GlobalPilotReadinessV1 is diagnostic evidence only.  It is never passed
    # to the concrete gate and cannot turn runtime authority green.
    authority = "fail_closed"
    return HiveRuntimeEvidence(
        schema_version=1,
        mode=config.mode,
        config_digest=config.digest,
        catalog_digest=snapshot.digest,
        repository=repository_kind,
        principal=principal_kind,
        authority=authority,
        state=state_kind,
        pilot=global_pilot_readiness.pilot,
        reason_codes=tuple(_bounded_reason(code) for code in reasons),
        mutation_performed=False,
        repository_count=repository_count,
        principal_count=principal_count,
        global_pilot_readiness=global_pilot_readiness,
    )


@dataclass(frozen=True, slots=True)
class HiveRuntime:
    """One coherent, private authority/repository/principal runtime bundle."""

    config: HiveConfig
    classes: Mapping[str, AgentClassProfile]
    state: HiveStateStore
    principals: PrincipalRegistry
    repositories: RepositoryRegistry
    authority: AuthorityEngine
    events: HiveEventStore
    catalog_digest: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.config, HiveConfig) or not isinstance(self.classes, Mapping):
            raise HiveRuntimeError("invalid_hive_runtime")
        if not isinstance(self.state, HiveStateStore) or not isinstance(self.principals, PrincipalRegistry):
            raise HiveRuntimeError("invalid_hive_runtime")
        if not isinstance(self.repositories, RepositoryRegistry) or not isinstance(self.authority, AuthorityEngine):
            raise HiveRuntimeError("invalid_hive_runtime")
        if not isinstance(self.events, HiveEventStore):
            raise HiveRuntimeError("invalid_hive_runtime")
        if self.catalog_digest is not None and not _is_catalog_digest(self.catalog_digest):
            raise HiveRuntimeError("invalid_hive_runtime")

    def public_status(self) -> dict[str, object]:
        """Return bounded status without roots, remotes, grants, or secrets."""

        return {
            "schema_version": 1,
            "mode": self.config.mode,
            "principal_count": len(self.principals.list(limit=256)),
            "repository_count": len(self.config.repositories),
            "feature_flags": dict(self.config.feature_flags),
            "raw_output": "not_returned",
        }


def build_hive_runtime(
    config: HiveConfig,
    classes: Mapping[str, AgentClassProfile],
    *,
    repository_roots: Mapping[str, Path],
    state_root: Path,
    materialize_principals: bool = False,
    read_only: bool = False,
    now: Callable[[], datetime] | None = None,
) -> HiveRuntime:
    """Assemble and verify one authoritative local runtime.

    ``materialize_principals`` is deliberately opt-in. With the default
    ``False`` the configured principal set must already exist with the exact
    configuration digest; missing or extra records deny the build. When it is
    enabled, only the configured principal records are created, in parent
    order, and the same parity check is applied afterwards.
    """

    if not isinstance(config, HiveConfig):
        raise HiveRuntimeError("invalid_hive_config")
    if not isinstance(classes, Mapping) or any(not isinstance(value, AgentClassProfile) for value in classes.values()):
        raise HiveRuntimeError("invalid_hive_classes")
    if any(raw.get("class_id") not in classes for raw in config.principals):
        raise HiveRuntimeError("unknown_hive_principal_class")
    if not isinstance(repository_roots, Mapping):
        raise HiveRuntimeError("invalid_repository_roots")
    if not isinstance(state_root, Path) or not state_root.is_absolute():
        raise HiveRuntimeError("invalid_hive_state_root")
    if type(read_only) is not bool:
        raise HiveRuntimeError("invalid_hive_runtime_mode")
    if read_only and materialize_principals:
        raise HiveRuntimeError("read_only_runtime_materialization_forbidden")
    repositories = _build_repositories(config, repository_roots)
    try:
        state = HiveStateStore(state_root, read_only=read_only)
    except HiveStateError as exc:
        raise HiveRuntimeError(str(exc)) from exc
    principals = PrincipalRegistry(state)
    expected = _expected_principals(config, classes)
    if materialize_principals:
        _materialize_principals(principals, expected)
    _verify_principal_parity(principals, expected)

    capabilities: dict[str, frozenset[str]] = {}
    for profile in classes.values():
        current = frozenset(profile.capabilities)
        previous = capabilities.get(profile.authority_profile)
        if previous is not None and previous != current:
            raise HiveRuntimeError("authority_profile_capability_conflict")
        capabilities[profile.authority_profile] = current
    authority = AuthorityEngine(
        AuthorityContext(principals, repositories, capabilities),
        state=state,
        now=now,
    )
    return HiveRuntime(config, dict(classes), state, principals, repositories, authority, HiveEventStore(state))


def _compose_hive_runtime_from_catalog_snapshot(
    config: HiveConfig,
    snapshot: AgentClassCatalogSnapshot,
    *,
    repository_roots: Mapping[str, Path],
    state_root: Path,
    expected_catalog_digest: str | None = None,
    materialize_principals: bool = False,
    now: Callable[[], datetime] | None = None,
) -> HiveRuntime:
    if not isinstance(snapshot, AgentClassCatalogSnapshot):
        raise HiveRuntimeError("invalid_catalog_snapshot")
    if expected_catalog_digest is not None and not _is_catalog_digest(expected_catalog_digest):
        raise HiveRuntimeError("catalog_digest_mismatch")
    if expected_catalog_digest is not None and not hmac.compare_digest(snapshot.digest, expected_catalog_digest):
        raise HiveRuntimeError("catalog_digest_mismatch")
    runtime = build_hive_runtime(
        config,
        snapshot.classes,
        repository_roots=repository_roots,
        state_root=state_root,
        materialize_principals=materialize_principals,
        now=now,
    )
    return replace(runtime, classes=snapshot.classes, catalog_digest=snapshot.digest)


def _build_repositories(config: HiveConfig, roots: Mapping[str, Path]) -> RepositoryRegistry:
    expected_ids = {str(raw.get("repo_id")) for raw in config.repositories}
    if set(roots) != expected_ids:
        raise HiveRuntimeError("repository_root_set_mismatch")
    bindings: list[RepositoryBinding] = []
    for raw in config.repositories:
        try:
            repo_id = raw["repo_id"]
            root = roots[repo_id]
            bindings.append(
                RepositoryBinding(
                    repo_id,
                    raw["remote_identity"],
                    root,
                    raw["default_branch"],
                    raw["config_digest"],
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise HiveRuntimeError("invalid_repository_binding") from exc
    try:
        return RepositoryRegistry(bindings)
    except (TypeError, ValueError) as exc:
        raise HiveRuntimeError("invalid_repository_registry") from exc


def _expected_principals(
    config: HiveConfig,
    classes: Mapping[str, AgentClassProfile],
) -> dict[str, Principal]:
    expected: dict[str, Principal] = {}
    for raw in config.principals:
        try:
            principal_id = raw["principal_id"]
            class_id = raw["class_id"]
            profile = classes[class_id]
            item = Principal(
                principal_id,
                class_id,
                raw["parent_principal_id"],
                profile.authority_profile,
                profile.scope_kind,
                raw["repo_id"],
                "active",
                config.digest,
                1,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise HiveRuntimeError("invalid_hive_principal") from exc
        if principal_id in expected:
            raise HiveRuntimeError("duplicate_hive_principal")
        expected[principal_id] = item
    return expected


def _materialize_principals(registry: PrincipalRegistry, expected: Mapping[str, Principal]) -> None:
    remaining = dict(expected)
    while remaining:
        progress = False
        for principal_id, item in tuple(remaining.items()):
            if item.parent_principal_id is not None and item.parent_principal_id in remaining:
                continue
            try:
                current = registry.get(principal_id)
            except ValueError:
                registry.create(item)
            else:
                if current != item:
                    raise HiveRuntimeError("hive_principal_state_mismatch")
            del remaining[principal_id]
            progress = True
        if not progress:
            raise HiveRuntimeError("hive_principal_parent_cycle")


def _verify_principal_parity(registry: PrincipalRegistry, expected: Mapping[str, Principal]) -> None:
    actual = {item.principal_id: item for item in registry.list(limit=256)}
    if set(actual) != set(expected):
        raise HiveRuntimeError("hive_principal_set_mismatch")
    if any(actual[principal_id] != item for principal_id, item in expected.items()):
        raise HiveRuntimeError("hive_principal_state_mismatch")


__all__ = [
    "GlobalPilotReadinessV1",
    "HiveRuntime",
    "HiveRuntimeError",
    "HiveRuntimeEvidence",
    "build_hive_runtime",
    "enforced_pilot_gate",
    "global_pilot_readiness_from_evidence",
    "read_global_pilot_readiness",
    "read_hive_runtime_evidence",
]
