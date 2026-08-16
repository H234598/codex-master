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
from pathlib import Path

from codex_master.hive.authority import AuthorityContext, AuthorityEngine
from codex_master.hive.config import AgentClassCatalogSnapshot, AgentClassProfile, HiveConfig, _is_catalog_digest
from codex_master.hive.events import HiveEventStore
from codex_master.hive.principals import Principal, PrincipalRegistry
from codex_master.hive.repositories import RepositoryBinding, RepositoryRegistry
from codex_master.hive.state import HiveStateStore


class HiveRuntimeError(ValueError):
    """Raised when the authoritative local Hive bundle cannot be assembled."""


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

    repositories = _build_repositories(config, repository_roots)
    state = HiveStateStore(state_root)
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


__all__ = ["HiveRuntime", "HiveRuntimeError", "build_hive_runtime"]
