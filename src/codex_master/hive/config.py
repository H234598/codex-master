"""Strict public Hive configuration and cross-reference loader."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import json
import re
from pathlib import Path
from types import MappingProxyType


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
    public_lifecycle: str = "ephemeral"
    allowed_lifecycles: tuple[str, ...] = ("ephemeral",)
    allowed_model_families: tuple[str, ...] = ("luna",)
    allowed_model_ids: tuple[str, ...] = ()
    min_reasoning: str = "low"
    max_reasoning: str = "xhigh"
    introduces_to_user: bool = False

    def __post_init__(self) -> None:
        for value, field in ((self.class_id, "class_id"), (self.role_kind, "role_kind"), (self.worker_kind, "worker_kind"), (self.scope_kind, "scope_kind"), (self.authority_profile, "authority_profile"), (self.identity_lifetime, "identity_lifetime"), (self.memory_lifetime, "memory_lifetime"), (self.home_policy, "home_policy"), (self.session_policy, "session_policy"), (self.write_mode, "write_mode")):
            if not isinstance(value, str) or not 1 <= len(value) <= 128 or any(ord(char) < 32 for char in value):
                raise HiveConfigError(f"invalid_{field}")
        if self.scope_kind not in {"global", "repository", "read", "write"} or self.write_mode not in {"none", "scoped", "integration"}:
            raise HiveConfigError("invalid_class_scope")
        if not _is_string_tuple(self.capabilities) or not _is_string_tuple(self.delegation_targets):
            raise HiveConfigError("invalid_class_lists")
        if isinstance(self.max_delegation_depth, bool) or not isinstance(self.max_delegation_depth, int) or not 0 <= self.max_delegation_depth <= 32:
            raise HiveConfigError("invalid_delegation_depth")
        if (
            self.public_lifecycle not in {"ephemeral", "binding", "persistent"}
            or not _is_string_tuple(self.allowed_lifecycles)
            or not _is_string_tuple(self.allowed_model_families)
            or not _is_string_tuple(self.allowed_model_ids)
            or self.public_lifecycle not in self.allowed_lifecycles
            or not self.allowed_model_families
            or any(not isinstance(model_id, str) or not model_id for model_id in self.allowed_model_ids)
            or len(set(self.allowed_model_ids)) != len(self.allowed_model_ids)
            or self.min_reasoning not in {"low", "medium", "high", "xhigh", "max"}
            or self.max_reasoning not in {"low", "medium", "high", "xhigh", "max"}
            or not isinstance(self.introduces_to_user, bool)
        ):
            raise HiveConfigError("invalid_class_resolver_profile")

    @property
    def resolver_profile(self) -> tuple[str, tuple[str, ...], tuple[str, ...], str, str]:
        return (
            self.public_lifecycle,
            self.allowed_lifecycles,
            self.allowed_model_families,
            self.min_reasoning,
            self.max_reasoning,
        )


def _is_string_tuple(value: object) -> bool:
    return type(value) is tuple and all(type(item) is str for item in value)


def _is_catalog_digest(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


def _profile_is_deeply_immutable(profile: object) -> bool:
    return type(profile) is AgentClassProfile and all(
        _is_string_tuple(getattr(profile, field))
        for field in (
            "capabilities",
            "delegation_targets",
            "allowed_lifecycles",
            "allowed_model_families",
            "allowed_model_ids",
        )
    )


@dataclass(frozen=True, slots=True)
class AgentClassCatalogSnapshot:
    classes: Mapping[str, AgentClassProfile]
    digest: str

    def __post_init__(self) -> None:
        if not _is_catalog_digest(self.digest) or not isinstance(self.classes, Mapping):
            raise HiveConfigError("invalid_class_catalog_snapshot")
        frozen: dict[str, AgentClassProfile] = {}
        for class_id, profile in self.classes.items():
            if type(class_id) is not str or type(profile) is not AgentClassProfile:
                raise HiveConfigError("invalid_class_catalog_snapshot")
            if not _profile_is_deeply_immutable(profile):
                raise HiveConfigError("invalid_class_catalog_snapshot")
            frozen[class_id] = profile
        object.__setattr__(self, "classes", MappingProxyType(frozen))


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
    return load_agent_class_catalog_snapshot(path).classes


def load_agent_class_catalog_snapshot(path: Path) -> AgentClassCatalogSnapshot:
    raw = _read_catalog_bytes(path)
    return load_agent_class_catalog_snapshot_bytes(raw)


def load_agent_class_catalog_snapshot_bytes(raw: bytes) -> AgentClassCatalogSnapshot:
    """Build one immutable catalog snapshot from already-attested bytes."""

    if type(raw) is not bytes:
        raise HiveConfigError("class_catalog_unavailable")
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    payload = _decode_catalog_mapping(raw)
    return AgentClassCatalogSnapshot(
        classes=_parse_agent_class_catalog(payload),
        digest=digest,
    )


def _parse_agent_class_catalog(payload: Mapping[str, object]) -> Mapping[str, AgentClassProfile]:
    if set(payload) != {"schema_version", "classes"} or payload["schema_version"] != 1 or not isinstance(payload["classes"], list):
        raise HiveConfigError("invalid_class_catalog")
    result: dict[str, AgentClassProfile] = {}
    fields = {"class_id", "role_kind", "worker_kind", "scope_kind", "authority_profile", "identity_lifetime", "memory_lifetime", "home_policy", "session_policy", "write_mode", "capabilities", "delegation_targets", "max_delegation_depth"}
    resolver_fields = {"public_lifecycle", "allowed_lifecycles", "allowed_model_families", "allowed_model_ids", "min_reasoning", "max_reasoning", "introduces_to_user"}
    for raw in payload["classes"]:
        if not isinstance(raw, Mapping) or not fields <= set(raw) or set(raw) - fields - resolver_fields:
            raise HiveConfigError("invalid_class_profile")
        try:
            item = AgentClassProfile(
                class_id=raw["class_id"], role_kind=raw["role_kind"], worker_kind=raw["worker_kind"],
                scope_kind=raw["scope_kind"], authority_profile=raw["authority_profile"],
                identity_lifetime=raw["identity_lifetime"], memory_lifetime=raw["memory_lifetime"],
                home_policy=raw["home_policy"], session_policy=raw["session_policy"], write_mode=raw["write_mode"],
                capabilities=tuple(raw["capabilities"]), delegation_targets=tuple(raw["delegation_targets"]),
                max_delegation_depth=raw["max_delegation_depth"],
                public_lifecycle=raw.get("public_lifecycle", "ephemeral"),
                allowed_lifecycles=tuple(raw.get("allowed_lifecycles", ("ephemeral",))),
                allowed_model_families=tuple(raw.get("allowed_model_families", ("luna",))),
                allowed_model_ids=tuple(raw.get("allowed_model_ids", ())),
                min_reasoning=raw.get("min_reasoning", "low"), max_reasoning=raw.get("max_reasoning", "xhigh"),
                introduces_to_user=raw.get("introduces_to_user", False),
            )
        except (KeyError, TypeError) as exc:
            raise HiveConfigError("invalid_class_profile") from exc
        if item.class_id in result:
            raise HiveConfigError("duplicate_class_id")
        result[item.class_id] = item
    return result


def _read_catalog_bytes(path: Path) -> bytes:
    if not isinstance(path, Path) or not path.is_absolute() or path.is_symlink():
        raise HiveConfigError("invalid_class_catalog_path")
    try:
        raw = path.read_bytes()
    except (OSError, UnicodeError):
        raise HiveConfigError("class_catalog_unavailable") from None
    if type(raw) is not bytes:
        raise HiveConfigError("class_catalog_unavailable")
    return raw


def _decode_catalog_mapping(raw: bytes) -> Mapping[str, object]:
    if type(raw) is not bytes:
        raise HiveConfigError("class_catalog_unavailable")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise HiveConfigError("class_catalog_unavailable") from None
    if not isinstance(payload, Mapping):
        raise HiveConfigError("invalid_class_catalog")
    return payload


def load_hive_config(path: Path, classes: Mapping[str, AgentClassProfile]) -> HiveConfig:
    if not isinstance(classes, Mapping) or any(not isinstance(value, AgentClassProfile) for value in classes.values()):
        raise HiveConfigError("invalid_class_catalog")
    payload = _load(path, "hive_config")
    return load_hive_config_payload(payload, classes)


def load_hive_config_bytes(raw: bytes, classes: Mapping[str, AgentClassProfile]) -> HiveConfig:
    """Parse a Hive config from bytes already read through a trusted FD."""

    if type(raw) is not bytes:
        raise HiveConfigError("hive_config_unavailable")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise HiveConfigError("hive_config_unavailable") from None
    if not isinstance(payload, Mapping):
        raise HiveConfigError("invalid_hive_config")
    return load_hive_config_payload(payload, classes)


def load_hive_config_payload(
    payload: Mapping[str, object], classes: Mapping[str, AgentClassProfile]
) -> HiveConfig:
    """Validate one decoded public config without rereading its source."""

    if not isinstance(classes, Mapping) or any(not isinstance(value, AgentClassProfile) for value in classes.values()):
        raise HiveConfigError("invalid_class_catalog")
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


__all__ = [
    "AgentClassCatalogSnapshot",
    "AgentClassProfile",
    "HiveConfig",
    "HiveConfigError",
    "load_agent_class_catalog",
    "load_agent_class_catalog_snapshot",
    "load_agent_class_catalog_snapshot_bytes",
    "load_hive_config",
    "load_hive_config_bytes",
    "load_hive_config_payload",
]
