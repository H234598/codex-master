"""Strict, secret-free model policy registry."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import json
from pathlib import Path


class ModelPolicyError(ValueError):
    """Raised for invalid model policy configuration."""


@dataclass(frozen=True, slots=True)
class ModelDefinition:
    model_id: str
    aliases: tuple[str, ...]
    role: str
    provider: str
    capabilities: tuple[str, ...]
    budget_key: str
    enabled: bool = True
    family: str = "primary"
    rank: int = 100
    reasoning_levels: tuple[str, ...] = ("low", "medium", "high", "xhigh")
    default_reasoning: str = "medium"
    cost_tier: str = "standard"
    spawn_behavior: str = "manual"

    def __post_init__(self) -> None:
        for value, field in (
            (self.model_id, "model_id"),
            (self.provider, "provider"),
            (self.budget_key, "budget_key"),
            (self.family, "family"),
            (self.cost_tier, "cost_tier"),
        ):
            if not isinstance(value, str) or not 1 <= len(value) <= 128 or any(ord(char) < 32 for char in value):
                raise ModelPolicyError(f"invalid_{field}")
        if self.role not in {"primary", "secondary_simple"}:
            raise ModelPolicyError("unknown_model_role")
        if not isinstance(self.aliases, tuple) or len(self.aliases) > 32 or len(set(self.aliases)) != len(self.aliases):
            raise ModelPolicyError("invalid_model_aliases")
        if not isinstance(self.capabilities, tuple) or len(self.capabilities) > 64:
            raise ModelPolicyError("invalid_model_capabilities")
        for value in (*self.aliases, *self.capabilities):
            if not isinstance(value, str) or not 1 <= len(value) <= 128 or any(ord(char) < 32 for char in value):
                raise ModelPolicyError("invalid_model_value")
        if not isinstance(self.enabled, bool):
            raise ModelPolicyError("invalid_model_enabled")
        if isinstance(self.rank, bool) or not isinstance(self.rank, int) or not 0 <= self.rank <= 10_000:
            raise ModelPolicyError("invalid_model_rank")
        valid_reasoning = {"low", "medium", "high", "xhigh", "max"}
        if (
            not isinstance(self.reasoning_levels, tuple)
            or not self.reasoning_levels
            or len(set(self.reasoning_levels)) != len(self.reasoning_levels)
            or any(level not in valid_reasoning for level in self.reasoning_levels)
            or self.default_reasoning not in self.reasoning_levels
        ):
            raise ModelPolicyError("invalid_model_reasoning")
        if self.spawn_behavior not in {"manual", "autonomous", "required"}:
            raise ModelPolicyError("invalid_model_spawn_behavior")


class ModelPolicyRegistry:
    def __init__(self, definitions: Iterable[ModelDefinition]) -> None:
        values = tuple(definitions)
        ids = [item.model_id for item in values]
        aliases = [alias for item in values for alias in item.aliases]
        budget_keys = [item.budget_key for item in values]
        if (
            len(set(ids)) != len(ids)
            or len(set(aliases)) != len(aliases)
            or set(ids) & set(aliases)
            or len(set(budget_keys)) != len(budget_keys)
        ):
            raise ModelPolicyError("duplicate_model_id_or_alias")
        if sum(item.role == "primary" for item in values) < 1:
            raise ModelPolicyError("primary_model_required")
        self._definitions = {item.model_id: item for item in values}
        self._aliases = {alias: item for item in values for alias in item.aliases}

    def get_exact(self, model_id: str) -> ModelDefinition | None:
        return self._definitions.get(model_id)

    def resolve_alias(self, alias: str) -> ModelDefinition | None:
        return self._aliases.get(alias)

    def public(self) -> tuple[dict[str, object], ...]:
        return tuple(
            {
                "model_id": item.model_id,
                "aliases": list(item.aliases),
                "role": item.role,
                "provider": item.provider,
                "capabilities": list(item.capabilities),
                "budget_key": item.budget_key,
                "enabled": item.enabled,
                "family": item.family,
                "rank": item.rank,
                "reasoning_levels": list(item.reasoning_levels),
                "default_reasoning": item.default_reasoning,
                "cost_tier": item.cost_tier,
                "spawn_behavior": item.spawn_behavior,
            }
            for item in self._definitions.values()
        )


def load_model_policy(path: Path) -> ModelPolicyRegistry:
    if not isinstance(path, Path) or not path.is_absolute() or path.is_symlink():
        raise ModelPolicyError("invalid_model_policy_path")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ModelPolicyError("model_policy_unavailable") from exc
    if not isinstance(payload, Mapping) or payload.get("schema_version") != 1 or set(payload) - {"schema_version", "models"}:
        raise ModelPolicyError("invalid_model_policy")
    raw_models = payload.get("models")
    if not isinstance(raw_models, list):
        raise ModelPolicyError("invalid_model_policy")
    definitions: list[ModelDefinition] = []
    for raw in raw_models:
        if not isinstance(raw, Mapping) or set(raw) - {
            "model_id", "aliases", "role", "provider", "capabilities", "budget_key", "enabled",
            "family", "rank", "reasoning_levels", "default_reasoning", "cost_tier", "spawn_behavior",
        }:
            raise ModelPolicyError("invalid_model_definition")
        try:
            definitions.append(
                ModelDefinition(
                    model_id=raw["model_id"],
                    aliases=tuple(raw.get("aliases", ())),
                    role=raw["role"],
                    provider=raw["provider"],
                    capabilities=tuple(raw.get("capabilities", ())),
                    budget_key=raw["budget_key"],
                    enabled=raw.get("enabled", True),
                    family=raw.get("family", "spark" if raw["role"] == "secondary_simple" else "primary"),
                    rank=raw.get("rank", 10 if raw["role"] == "secondary_simple" else 100),
                    reasoning_levels=tuple(raw.get("reasoning_levels", ("low", "medium", "high", "xhigh"))),
                    default_reasoning=raw.get("default_reasoning", "medium"),
                    cost_tier=raw.get("cost_tier", raw["budget_key"]),
                    spawn_behavior=raw.get("spawn_behavior", "manual"),
                )
            )
        except (KeyError, TypeError) as exc:
            raise ModelPolicyError("invalid_model_definition") from exc
    return ModelPolicyRegistry(definitions)


__all__ = ["ModelDefinition", "ModelPolicyError", "ModelPolicyRegistry", "load_model_policy"]
