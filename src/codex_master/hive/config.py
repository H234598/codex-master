"""Strict public Hive configuration and cross-reference loader."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path


class HiveConfigError(ValueError):
    """Raised for invalid Hive configuration."""


@dataclass(frozen=True, slots=True)
class AgentClassProfile:
    class_id: str
    role_kind: str
    worker_kind: str
    scope_kind: str
    authority_profile: str
    identity_lifetime: str
    memory_lifetime: str
    home_policy: str
    session_policy: str
    write_mode: str
    capabilities: tuple[str, ...]
    delegation_targets: tuple[str, ...]
    max_delegation_depth: int

    def __post_init__(self) -> None:
        for value, field in ((self.class_id, "class_id"), (self.role_kind, "role_kind"), (self.worker_kind, "worker_kind"), (self.scope_kind, "scope_kind"), (self.authority_profile, "authority_profile"), (self.identity_lifetime, "identity_lifetime"), (self.memory_lifetime, "memory_lifetime"), (self.home_policy, "home_policy"), (self.session_policy, "session_policy"), (self.write_mode, "write_mode")):
            if not isinstance(value, str) or not 1 <= len(value) <= 128 or any(ord(char) < 32 for char in value):
                raise HiveConfigError(f"invalid_{field}")
        if self.scope_kind not in {"global", "repository", "read", "write"} or self.write_mode not in {"none", "scoped", "integration"}:
            raise HiveConfigError("invalid_class_scope")
        if not isinstance(self.capabilities, tuple) or not isinstance(self.delegation_targets, tuple):
            raise HiveConfigError("invalid_class_lists")
        if isinstance(self.max_delegation_depth, bool) or not isinstance(self.max_delegation_depth, int) or not 0 <= self.max_delegation_depth <= 32:
            raise HiveConfigError("invalid_delegation_depth")


@dataclass(frozen=True, slots=True)
class HiveConfig:
    schema_version: int
    mode: str
    repositories: tuple[Mapping[str, object], ...]
    principals: tuple[Mapping[str, object], ...]
    feature_flags: Mapping[str, bool]
    digest: str

    def __post_init__(self) -> None:
        if self.schema_version != 1 or self.mode not in {"disabled", "shadow", "enforced"}:
            raise HiveConfigError("invalid_hive_config")
        if not isinstance(self.repositories, tuple) or not isinstance(self.principals, tuple):
            raise HiveConfigError("invalid_hive_config_lists")
        if not isinstance(self.feature_flags, Mapping) or any(not isinstance(value, bool) for value in self.feature_flags.values()):
            raise HiveConfigError("invalid_hive_feature_flags")
        if not isinstance(self.digest, str) or not self.digest.startswith("sha256:"):
            raise HiveConfigError("invalid_hive_config_digest")


def load_agent_class_catalog(path: Path) -> Mapping[str, AgentClassProfile]:
    payload = _load(path, "class_catalog")
    if set(payload) != {"schema_version", "classes"} or payload["schema_version"] != 1 or not isinstance(payload["classes"], list):
        raise HiveConfigError("invalid_class_catalog")
    result: dict[str, AgentClassProfile] = {}
    fields = {"class_id", "role_kind", "worker_kind", "scope_kind", "authority_profile", "identity_lifetime", "memory_lifetime", "home_policy", "session_policy", "write_mode", "capabilities", "delegation_targets", "max_delegation_depth"}
    for raw in payload["classes"]:
        if not isinstance(raw, Mapping) or set(raw) != fields:
            raise HiveConfigError("invalid_class_profile")
        try:
            item = AgentClassProfile(
                raw["class_id"], raw["role_kind"], raw["worker_kind"], raw["scope_kind"], raw["authority_profile"],
                raw["identity_lifetime"], raw["memory_lifetime"], raw["home_policy"], raw["session_policy"], raw["write_mode"],
                tuple(raw["capabilities"]), tuple(raw["delegation_targets"]), raw["max_delegation_depth"],
            )
        except (KeyError, TypeError) as exc:
            raise HiveConfigError("invalid_class_profile") from exc
        if item.class_id in result:
            raise HiveConfigError("duplicate_class_id")
        result[item.class_id] = item
    return result


def load_hive_config(path: Path, classes: Mapping[str, AgentClassProfile]) -> HiveConfig:
    if not isinstance(classes, Mapping) or any(not isinstance(value, AgentClassProfile) for value in classes.values()):
        raise HiveConfigError("invalid_class_catalog")
    payload = _load(path, "hive_config")
    allowed = {"schema_version", "mode", "repositories", "principals", "feature_flags"}
    if set(payload) != allowed or payload.get("schema_version") != 1 or not isinstance(payload.get("repositories"), list) or not isinstance(payload.get("principals"), list) or not isinstance(payload.get("feature_flags"), Mapping):
        raise HiveConfigError("invalid_hive_config")
    repositories = tuple(_strict_mapping(value, {"repo_id", "remote_identity", "default_branch", "config_digest"}) for value in payload["repositories"])
    repo_ids = [value["repo_id"] for value in repositories]
    if len(set(repo_ids)) != len(repo_ids) or any(not isinstance(value, str) or not value for value in repo_ids):
        raise HiveConfigError("invalid_hive_repositories")
    principals = tuple(_strict_mapping(value, {"principal_id", "class_id", "parent_principal_id", "repo_id"}) for value in payload["principals"])
    principal_ids = [value["principal_id"] for value in principals]
    if len(set(principal_ids)) != len(principal_ids):
        raise HiveConfigError("duplicate_principal_id")
    for value in principals:
        class_id = value["class_id"]
        if class_id not in classes:
            raise HiveConfigError("unknown_principal_class")
        profile = classes[class_id]
        repo_id = value["repo_id"]
        if profile.scope_kind == "global" and repo_id is not None:
            raise HiveConfigError("global_principal_has_repository")
        if profile.scope_kind == "repository" and (repo_id is None or repo_id not in repo_ids):
            raise HiveConfigError("repository_principal_missing_repository")
    flags = {key: value for key, value in payload["feature_flags"].items() if isinstance(key, str) and isinstance(value, bool)}
    if len(flags) != len(payload["feature_flags"]):
        raise HiveConfigError("invalid_hive_feature_flags")
    canonical = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = "sha256:" + hashlib.sha256(canonical).hexdigest()
    return HiveConfig(1, payload["mode"], repositories, principals, flags, digest)


def _load(path: Path, name: str) -> Mapping[str, object]:
    if not isinstance(path, Path) or not path.is_absolute() or path.is_symlink():
        raise HiveConfigError(f"invalid_{name}_path")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise HiveConfigError(f"{name}_unavailable") from exc
    if not isinstance(payload, Mapping):
        raise HiveConfigError(f"invalid_{name}")
    return payload


def _strict_mapping(value: object, fields: set[str]) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise HiveConfigError("invalid_hive_config_entry")
    return dict(value)


__all__ = ["AgentClassProfile", "HiveConfig", "HiveConfigError", "load_agent_class_catalog", "load_hive_config"]
