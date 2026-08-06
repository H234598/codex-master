from pathlib import Path
import json

import pytest

from codex_master.hive.config import load_agent_class_catalog, load_hive_config
from codex_master.selection import SelectionError, normalize_usage_v2
from codex_master.selection.config import load_selection_policy
from codex_master.selection.model_policy import load_model_policy
from codex_master.selection.state import ResourceStateError, migrate_resource_state


ROOT = Path(__file__).resolve().parents[1]


def read_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def test_public_schemas_examples_and_hive_fixtures_are_json_and_secret_free() -> None:
    paths = sorted((ROOT / "schemas").glob("*.json")) + sorted((ROOT / "examples").glob("*.json"))
    paths += sorted((ROOT / "tests" / "fixtures").rglob("*.json"))
    assert paths
    for path in paths:
        encoded = path.read_text(encoding="utf-8")
        read_json(path)
        assert "api-token" not in encoded.lower()
        assert "gemini_api_key" not in encoded.lower()


def test_hive_shadow_and_enforced_fixture_configs_load() -> None:
    classes = load_agent_class_catalog(ROOT / "tests/fixtures/hive/classes-valid.json")
    shadow = load_hive_config(ROOT / "tests/fixtures/hive/hive-shadow-valid.json", classes)
    enforced = load_hive_config(ROOT / "tests/fixtures/hive/hive-enforced-valid.json", classes)
    assert shadow.mode == "shadow"
    assert enforced.mode == "enforced"
    assert enforced.repositories[0]["repo_id"] == "repo-one"


def test_selection_usage_and_model_policy_fixtures_normalize() -> None:
    fixtures = ROOT / "tests/fixtures/selection"
    for name in ("usage-v2-standard-and-spark.json", "usage-v2-remaining-100-rolling.json", "usage-v2-consumed-100.json", "usage-v2-five-hour.json", "usage-v2-multiple-windows.json", "usage-v2-stale.json"):
        windows = normalize_usage_v2(read_json(fixtures / name))
        assert windows
    assert normalize_usage_v2(read_json(fixtures / "usage-v1-main.json")) is None
    assert len(load_model_policy(fixtures / "model-policy-valid.json").public()) == 2


def test_private_selection_policy_example_loads_without_opening_execution() -> None:
    config = load_selection_policy(ROOT / "examples/codex-selection-policy.json")
    assert config.mode.value == "shadow"
    assert config.selection_policy().sp0 is False
    assert config.allows_pilot(teamleader="synthetic-teamlead", account="synthetic-account-a", operation="assign") is False


def test_selection_state_fixtures_preserve_schema_failure_semantics() -> None:
    fixtures = ROOT / "tests/fixtures/selection"
    assert migrate_resource_state(read_json(fixtures / "state-v0.json")).revision == 3
    assert migrate_resource_state(read_json(fixtures / "state-v1.json")).revision == 4
    with pytest.raises(ResourceStateError, match="unsupported_resource_schema"):
        migrate_resource_state(read_json(fixtures / "state-corrupt.json"))


def test_fixture_loader_rejects_unknown_usage_shape() -> None:
    with pytest.raises(SelectionError, match="invalid_usage_window"):
        normalize_usage_v2({"schema_version": 2, "limit_windows": [{"secret": "synthetic"}]})
