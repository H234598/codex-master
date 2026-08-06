from pathlib import Path

import pytest

from codex_master.selection.model_policy import ModelDefinition, ModelPolicyError, ModelPolicyRegistry, load_model_policy


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
