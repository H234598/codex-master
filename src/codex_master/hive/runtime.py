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
from datetime import datetime
import hmac
import os
from pathlib import Path
import re
import stat

from codex_master.hive.authority import AuthorityContext, AuthorityEngine
from codex_master.hive.config import (
    AgentClassCatalogSnapshot,
    AgentClassProfile,
    HiveConfig,
    HiveConfigError,
    _is_catalog_digest,
    load_agent_class_catalog_snapshot,
    load_hive_config,
)
from codex_master.hive.events import HiveEventError, HiveEventStore
from codex_master.hive.principals import Principal, PrincipalRegistry
from codex_master.hive.repositories import RepositoryBinding, RepositoryRegistry
from codex_master.hive.state import HiveStateError, HiveStateStore


class HiveRuntimeError(ValueError):
    """Raised when the authoritative local Hive bundle cannot be assembled."""


_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_RUNTIME_STATES = frozenset({"ready", "not_configured", "invalid", "unavailable"})
_PILOT_REPOSITORY = "codex-master"
_PILOT_QUEEN = "queen-codex-master"
_PILOT_REMOTE = "https://github.com/H234598/codex-master.git"
_PILOT_FEATURE_FLAGS = frozenset({"sp0_passive", "sp1_deadline", "sp2_secondary_model", "sp3_fairness"})


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


def enforced_pilot_gate(
    config: HiveConfig,
    classes: Mapping[str, AgentClassProfile],
    dynamic_account_evidence: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Evaluate the closed pilot allowlist without accepting an account name."""

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
    if not isinstance(dynamic_account_evidence, Mapping):
        return {"allowed": False, "reason_code": "pilot_account_attestation_missing", "raw_output": "not_returned"}
    account_ok = (
        dynamic_account_evidence.get("fresh") is True
        and dynamic_account_evidence.get("model_family") == "sol"
        and dynamic_account_evidence.get("reasoning") == "max"
        and dynamic_account_evidence.get("long_lived") is True
    )
    return {
        "allowed": account_ok,
        "reason_code": "pilot_ready" if account_ok else "pilot_account_attestation_invalid",
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


def read_hive_runtime_evidence(
    *,
    catalog_path: Path | None = None,
    config_path: Path | None = None,
    state_root: Path | None = None,
    repository_roots: Mapping[str, Path] | None = None,
    dynamic_account_evidence: Mapping[str, object] | None = None,
    now: Callable[[], datetime] | None = None,
) -> HiveRuntimeEvidence:
    """Read one canonical Hive projection without creating or repairing state."""

    repository_root = _default_repository_root()
    catalog_path = catalog_path or repository_root / "codex-agent-classes.json"
    config_path = config_path or repository_root / "codex-hive.json"
    state_root = state_root or _default_hive_state_root()
    empty = {
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
        not isinstance(catalog_path, Path)
        or not catalog_path.is_absolute()
        or not isinstance(config_path, Path)
        or not config_path.is_absolute()
        or not isinstance(state_root, Path)
        or not state_root.is_absolute()
    ):
        return HiveRuntimeEvidence(**empty, reason_codes=("hive_runtime_unavailable",))
    try:
        snapshot = load_agent_class_catalog_snapshot(catalog_path)
        config = load_hive_config(config_path, snapshot.classes)
    except (HiveConfigError, OSError, TypeError, ValueError):
        return HiveRuntimeEvidence(**empty, reason_codes=("hive_config_unavailable",))

    state_kind = _existing_state_kind(state_root)
    repository_kind = "not_configured" if not config.repositories else "unavailable"
    principal_kind = "not_configured" if not config.principals else (
        "not_configured" if state_kind == "not_configured" else state_kind
    )
    reasons: list[str] = []
    if not config.repositories:
        reasons.append("repository_not_configured")
    elif repository_roots is None:
        reasons.append("repository_root_unavailable")
    if not config.principals:
        reasons.append("principal_not_configured")
    if state_kind == "not_configured":
        reasons.append("state_not_configured")
    elif state_kind != "ready":
        reasons.append("state_unavailable" if state_kind == "unavailable" else "state_invalid")

    if config.repositories and repository_roots is not None:
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

    runtime: HiveRuntime | None = None
    if state_kind == "ready" and repository_kind == "ready" and config.principals:
        try:
            runtime = build_hive_runtime(
                config,
                snapshot.classes,
                repository_roots=dict(repository_roots or {}),
                state_root=state_root,
                materialize_principals=False,
                now=now,
                read_only=True,
            )
        except (HiveRuntimeError, HiveStateError, HiveEventError, OSError, TypeError, ValueError):
            reasons.append("hive_runtime_invalid")
            principal_kind = "invalid"
            runtime = None

    if runtime is not None:
        repository_kind = "ready"
        principal_kind = "ready"
        state_kind = "ready"
        repository_count = len(config.repositories)
        principal_count = len(config.principals)
    else:
        repository_count = len(config.repositories)
        principal_count = len(config.principals) if state_kind == "ready" and config.principals else 0
    reasons = list(dict.fromkeys(reasons))
    pilot = enforced_pilot_gate(config, snapshot.classes, dynamic_account_evidence)
    authority = (
        "ready"
        if runtime is not None and config.mode == "enforced" and pilot["allowed"] is True
        else "fail_closed"
    )
    return HiveRuntimeEvidence(
        schema_version=1,
        mode=config.mode,
        config_digest=config.digest,
        catalog_digest=snapshot.digest,
        repository=repository_kind,
        principal=principal_kind,
        authority=authority,
        state=state_kind,
        pilot="ready" if pilot["allowed"] is True else "blocked",
        reason_codes=tuple(_bounded_reason(code) for code in reasons),
        mutation_performed=False,
        repository_count=repository_count,
        principal_count=principal_count,
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
    "HiveRuntime",
    "HiveRuntimeError",
    "HiveRuntimeEvidence",
    "build_hive_runtime",
    "enforced_pilot_gate",
    "read_hive_runtime_evidence",
]
