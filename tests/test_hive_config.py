from dataclasses import FrozenInstanceError, replace
import hashlib
import json
from pathlib import Path
import traceback

import pytest

from codex_master.hive.config import (
    AgentClassCatalogSnapshot,
    HiveConfigError,
    load_agent_class_catalog,
    load_agent_class_catalog_snapshot,
    load_agent_class_catalog_snapshot_bytes,
    load_hive_config,
    load_hive_config_bytes,
)


ROOT = Path(__file__).resolve().parents[1]


def test_public_class_and_hive_examples_load_with_stable_digest() -> None:
    classes = load_agent_class_catalog(ROOT / "codex-agent-classes.json")
    config = load_hive_config(ROOT / "codex-hive.json", classes)
    assert classes["gottbiene"].scope_kind == "global"
    assert config.mode == "shadow"
    assert config.digest.startswith("sha256:")


def test_public_classes_expose_resolver_profiles() -> None:
    classes = load_agent_class_catalog(ROOT / "codex-agent-classes.json")

    assert classes["goettin"].resolver_profile == ("persistent", ("persistent",), ("sol",), "max", "max")
    assert classes["gottbiene"].resolver_profile == ("persistent", ("persistent",), ("sol",), "max", "max")
    assert classes["koenigin"].resolver_profile == ("persistent", ("persistent",), ("sol",), "max", "max")
    assert classes["teamleiterin"].resolver_profile == ("persistent", ("persistent",), ("terra",), "xhigh", "xhigh")
    assert classes["teamleiterin"].allowed_model_ids == ("gpt-5.6-terra",)
    assert classes["spezialistin"].resolver_profile == ("binding", ("binding",), ("spark", "luna", "terra", "sol"), "high", "xhigh")
    assert classes["arbeitsbiene"].resolver_profile[0] == "ephemeral"


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


def test_catalog_snapshot_reads_exactly_once_and_hashes_that_same_bytes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    catalog = tmp_path / "classes.json"
    raw = (ROOT / "codex-agent-classes.json").read_bytes()
    calls = 0

    def one_read(path: Path) -> bytes:
        nonlocal calls
        assert path == catalog
        calls += 1
        if calls != 1:
            raise AssertionError("second_catalog_byte_read")
        return raw

    monkeypatch.setattr(Path, "read_bytes", one_read)
    snapshot = load_agent_class_catalog_snapshot(catalog)
    assert calls == 1
    assert snapshot.digest == "sha256:" + hashlib.sha256(raw).hexdigest()
    assert snapshot.classes["teamleiterin"].class_id == "teamleiterin"


def test_attested_catalog_and_hive_config_bytes_use_the_same_strict_contract() -> None:
    catalog_raw = (ROOT / "codex-agent-classes.json").read_bytes()
    config_raw = (ROOT / "codex-hive.json").read_bytes()

    snapshot = load_agent_class_catalog_snapshot_bytes(catalog_raw)
    config = load_hive_config_bytes(config_raw, snapshot.classes)

    assert snapshot.digest == "sha256:" + hashlib.sha256(catalog_raw).hexdigest()
    assert config.mode == "shadow"
    with pytest.raises(HiveConfigError, match="hive_config_unavailable"):
        load_hive_config_bytes(b"{", snapshot.classes)


def test_catalog_snapshot_is_deeply_immutable_after_direct_construction() -> None:
    profile = load_agent_class_catalog(ROOT / "codex-agent-classes.json")["teamleiterin"]
    source = {"teamleiterin": profile}
    snapshot = AgentClassCatalogSnapshot(source, "sha256:" + "a" * 64)
    source.clear()
    assert tuple(snapshot.classes) == ("teamleiterin",)
    with pytest.raises(TypeError):
        snapshot.classes["forged"] = profile  # type: ignore[index]
    with pytest.raises(FrozenInstanceError):
        snapshot.classes["teamleiterin"].capabilities += ("forged",)
    with pytest.raises(AttributeError):
        snapshot.classes["teamleiterin"].capabilities.append("forged")  # type: ignore[attr-defined]
    with pytest.raises(HiveConfigError, match="invalid_class_resolver_profile"):
        replace(profile, allowed_lifecycles=["persistent"])


def test_catalog_snapshot_missing_file_is_fail_closed_and_publicly_redacted(tmp_path: Path) -> None:
    marker = "catalog-payload-class-member-principal-repo-home-session-journal-path-secret"
    missing = tmp_path / f"{marker}.json"

    with pytest.raises(HiveConfigError) as raised:
        load_agent_class_catalog_snapshot(missing)

    assert str(raised.value) == "class_catalog_unavailable"
    assert raised.value.__cause__ is None
    rendered = "".join(traceback.format_exception(raised.value))
    assert marker not in rendered
    assert str(tmp_path) not in rendered


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (b'{"catalog-payload-class-member-principal-repo-home-session-journal-secret":"\\xff"}', "class_catalog_unavailable"),
        (b'{"catalog-payload-class-member-principal-repo-home-session-journal-secret":[]}', "invalid_class_catalog"),
    ],
)
def test_catalog_snapshot_invalid_input_is_fail_closed_and_publicly_redacted(
    tmp_path: Path, raw: bytes, reason: str
) -> None:
    marker = "catalog-payload-class-member-principal-repo-home-session-journal-secret"
    catalog = tmp_path / f"{marker}.json"
    catalog.write_bytes(raw)

    with pytest.raises(HiveConfigError) as raised:
        load_agent_class_catalog_snapshot(catalog)

    assert str(raised.value) == reason
    assert raised.value.__cause__ is None
    rendered = "".join(traceback.format_exception(raised.value))
    assert marker not in rendered
    assert str(catalog) not in rendered
