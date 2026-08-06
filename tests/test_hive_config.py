import json
from pathlib import Path

import pytest

from codex_master.hive.config import HiveConfigError, load_agent_class_catalog, load_hive_config


ROOT = Path(__file__).resolve().parents[1]


def test_public_class_and_hive_examples_load_with_stable_digest() -> None:
    classes = load_agent_class_catalog(ROOT / "codex-agent-classes.json")
    config = load_hive_config(ROOT / "codex-hive.json", classes)
    assert classes["gottbiene"].scope_kind == "global"
    assert config.mode == "shadow"
    assert config.digest.startswith("sha256:")


def test_checked_in_example_configs_are_public_and_loadable() -> None:
    examples = ROOT / "examples"
    classes = load_agent_class_catalog(examples / "codex-agent-classes.json")
    config = load_hive_config(examples / "codex-hive.json", classes)
    policy = json.loads((examples / "codex-model-policy.json").read_text(encoding="utf-8"))
    assert config.mode == "shadow"
    assert policy["schema_version"] == 1
    assert all("token" not in json.dumps(item).lower() for item in policy["models"])


def test_hive_loader_rejects_unknown_class_and_global_repository_scope(tmp_path: Path) -> None:
    classes_path = tmp_path / "classes.json"
    classes_path.write_text((ROOT / "codex-agent-classes.json").read_text(encoding="utf-8"), encoding="utf-8")
    classes = load_agent_class_catalog(classes_path)
    config_path = tmp_path / "hive.json"
    config_path.write_text('{"schema_version":1,"mode":"shadow","repositories":[],"principals":[{"principal_id":"god","class_id":"unknown","parent_principal_id":null,"repo_id":null}],"feature_flags":{}}', encoding="utf-8")
    with pytest.raises(HiveConfigError, match="unknown_principal_class"):
        load_hive_config(config_path, classes)
