from datetime import datetime, timezone
from pathlib import Path
import subprocess

import pytest

from codex_master.hive.config import load_agent_class_catalog, load_hive_config
from codex_master.hive.runtime import HiveRuntimeError, build_hive_runtime
from codex_master.hive.repositories import RepositoryRegistry
from codex_master.server import AgentError, build_server_admission_runtime


ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 8, 6, 12, tzinfo=timezone.utc)


def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo-one"
    root.mkdir()
    subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
    subprocess.run(
        ["git", "-C", str(root), "config", "remote.origin.url", "https://github.com/example/repo.git"],
        check=True,
    )
    return root


def config_bundle():
    classes = load_agent_class_catalog(ROOT / "tests/fixtures/hive/classes-valid.json")
    config = load_hive_config(ROOT / "tests/fixtures/hive/hive-enforced-valid.json", classes)
    return classes, config


def test_runtime_materializes_and_reloads_exact_authoritative_principal_set(tmp_path: Path) -> None:
    classes, config = config_bundle()
    roots = {"repo-one": repo(tmp_path)}

    created = build_hive_runtime(
        config,
        classes,
        repository_roots=roots,
        state_root=tmp_path / "state",
        materialize_principals=True,
        now=lambda: NOW,
    )
    assert created.public_status() == {
        "schema_version": 1,
        "mode": "enforced",
        "principal_count": 2,
        "repository_count": 1,
        "feature_flags": {
            "sp0_passive": False,
            "sp1_deadline": False,
            "sp2_secondary_model": False,
            "sp3_fairness": False,
        },
        "raw_output": "not_returned",
    }
    assert created.repositories.validate("repo-one").allowed is True

    reloaded = build_hive_runtime(
        config,
        classes,
        repository_roots=roots,
        state_root=tmp_path / "state",
        now=lambda: NOW,
    )
    assert [item.principal_id for item in reloaded.principals.list()] == [
        "godbee-main",
        "queen-repo-one",
    ]


def test_runtime_requires_explicit_materialization_and_rejects_root_mismatch(tmp_path: Path) -> None:
    classes, config = config_bundle()
    roots = {"repo-one": repo(tmp_path)}

    with pytest.raises(HiveRuntimeError, match="hive_principal_set_mismatch"):
        build_hive_runtime(
            config,
            classes,
            repository_roots=roots,
            state_root=tmp_path / "state",
            now=lambda: NOW,
        )
    with pytest.raises(HiveRuntimeError, match="repository_root_set_mismatch"):
        build_hive_runtime(
            config,
            classes,
            repository_roots={},
            state_root=tmp_path / "other-state",
            materialize_principals=True,
            now=lambda: NOW,
        )


def test_runtime_rejects_principal_state_drift(tmp_path: Path) -> None:
    classes, config = config_bundle()
    roots = {"repo-one": repo(tmp_path)}
    build_hive_runtime(
        config,
        classes,
        repository_roots=roots,
        state_root=tmp_path / "state",
        materialize_principals=True,
        now=lambda: NOW,
    )
    state_file = tmp_path / "state" / "principals.json"
    payload = state_file.read_text(encoding="utf-8").replace("queen-repo-one", "queen-drifted")
    state_file.write_text(payload, encoding="utf-8")
    with pytest.raises(HiveRuntimeError, match="hive_principal_state_invalid|hive_principal_set_mismatch"):
        build_hive_runtime(
            config,
            classes,
            repository_roots=roots,
            state_root=tmp_path / "state",
            now=lambda: NOW,
        )


def test_server_factory_accepts_one_bundle_and_rejects_split_authority_state(tmp_path: Path) -> None:
    classes, config = config_bundle()
    bundle = build_hive_runtime(
        config,
        classes,
        repository_roots={"repo-one": repo(tmp_path)},
        state_root=tmp_path / "state",
        materialize_principals=True,
        now=lambda: NOW,
    )
    assert build_server_admission_runtime(hive_runtime=bundle) is not None
    with pytest.raises(AgentError, match="conflicting_repository_runtime"):
        build_server_admission_runtime(
            hive_runtime=bundle,
            repository_registry=RepositoryRegistry(()),
        )
