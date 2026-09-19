from pathlib import Path

import pytest

from the_hive.agent_resolver import build_selection_offer, policies_from_catalogs
from the_hive.hive.config import load_agent_class_catalog
from the_hive.selection.model_policy import (
    ModelDefinition,
    ModelPolicyError,
    ModelPolicyRegistry,
    load_model_policy,
    load_model_policy_bytes,
)


def test_model_policy_resolves_exact_ids_and_aliases_without_duplicate_budget_keys() -> None:
    registry = ModelPolicyRegistry((ModelDefinition("gpt-primary", ("primary",), "primary", "openai", ("tools",), "standard"),))
    assert registry.get_exact("gpt-primary").role == "primary"
    assert registry.resolve_alias("primary").model_id == "gpt-primary"
    with pytest.raises(ModelPolicyError, match="duplicate_model_id_or_alias"):
        ModelPolicyRegistry((
            ModelDefinition("gpt-primary", ("same",), "primary", "openai", (), "standard"),
            ModelDefinition("spark", ("same",), "secondary_simple", "openai", (), "spark"),
        ))
    with pytest.raises(ModelPolicyError, match="duplicate_model_id_or_alias"):
        ModelPolicyRegistry((
            ModelDefinition("gpt-primary", (), "primary", "openai", (), "shared"),
            ModelDefinition("spark", (), "secondary_simple", "openai", (), "shared"),
        ))


def test_model_policy_loader_rejects_unknown_fields_and_loads_strict_document(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    path.write_text('{"schema_version":1,"models":[{"model_id":"gpt-primary","aliases":[],"role":"primary","provider":"openai","capabilities":["tools"],"budget_key":"standard"}]}', encoding="utf-8")
    assert load_model_policy(path).get_exact("gpt-primary") is not None
    path.write_text('{"schema_version":1,"models":[],"secret":"no"}', encoding="utf-8")
    with pytest.raises(ModelPolicyError, match="invalid_model_policy"):
        load_model_policy(path)


def test_model_policy_loads_resolver_metadata() -> None:
    registry = load_model_policy(Path(__file__).resolve().parents[1] / "codex-model-policy.json")

    sol = registry.get_exact("gpt-5.6-sol")
    assert sol is not None
    assert sol.family == "sol"
    assert sol.rank == 40
    assert sol.reasoning_levels == ("xhigh", "max")
    assert sol.default_reasoning == "xhigh"
    assert sol.spawn_behavior == "manual"
    assert {item["family"] for item in registry.public()} == {"luna", "terra", "sol"}


def test_model_policy_bytes_loader_matches_the_strict_path_loader() -> None:
    path = Path(__file__).resolve().parents[1] / "codex-model-policy.json"
    assert load_model_policy_bytes(path.read_bytes()).public() == load_model_policy(path).public()


def test_active_policy_does_not_turn_a_spark_id_only_availability_into_an_offer() -> None:
    root = Path(__file__).resolve().parents[1]
    active_policy = root / "codex-model-policy.json"
    registry = load_model_policy(active_policy)

    assert active_policy.read_bytes() == (root / "examples/codex-model-policy.json").read_bytes()
    assert registry.get_exact("gpt-5.3-codex-spark") is None
    assert registry.resolve_alias("spark") is None
    assert all(item["family"] != "spark" for item in registry.public())

    classes, models = policies_from_catalogs(
        load_agent_class_catalog(root / "codex-agent-classes.json"), registry
    )
    offer = build_selection_offer(
        classes=classes,
        models=models,
        available_models={item.model_id for item in models} | {"gpt-5.3-codex-spark"},
    )

    assert "gpt-5.3-codex-spark" not in offer.models
    assert all(option.model != "gpt-5.3-codex-spark" for option in offer.options)
