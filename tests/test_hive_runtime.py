from datetime import datetime, timezone
from pathlib import Path
import subprocess
import traceback

import pytest

from codex_master.hive.config import load_agent_class_catalog, load_agent_class_catalog_snapshot, load_hive_config
from codex_master.hive.events import HiveEventStore
from codex_master.hive.runtime import (
    HiveRuntimeError,
    _compose_hive_runtime_from_catalog_snapshot,
    build_hive_runtime,
)
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


def snapshot_bundle(tmp_path: Path):
    catalog = tmp_path / "classes.json"
    catalog.write_bytes((ROOT / "tests/fixtures/hive/classes-valid.json").read_bytes())
    snapshot = load_agent_class_catalog_snapshot(catalog)
    config = load_hive_config(ROOT / "tests/fixtures/hive/hive-enforced-valid.json", snapshot.classes)
    return snapshot, config


def test_snapshot_composer_pins_digest_and_reuses_immutable_classes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    snapshot, config = snapshot_bundle(tmp_path)
    monkeypatch.setattr(Path, "read_bytes", lambda _: (_ for _ in ()).throw(AssertionError("composer_read")))
    runtime = _compose_hive_runtime_from_catalog_snapshot(
        config,
        snapshot,
        repository_roots={"repo-one": repo(tmp_path)},
        state_root=tmp_path / "state",
        expected_catalog_digest=snapshot.digest,
        materialize_principals=True,
        now=lambda: NOW,
    )
    assert runtime.catalog_digest == snapshot.digest
    assert runtime.classes is snapshot.classes
    assert isinstance(runtime.events, HiveEventStore)


def test_snapshot_composer_rejects_digest_mismatch_type_length_and_case(tmp_path: Path) -> None:
    snapshot, config = snapshot_bundle(tmp_path)
    drifted_path = tmp_path / "classes-drifted.json"
    drifted_path.write_bytes((ROOT / "tests/fixtures/hive/classes-valid.json").read_bytes() + b"\n")
    drifted = load_agent_class_catalog_snapshot(drifted_path)
    with pytest.raises(HiveRuntimeError, match="catalog_digest_mismatch"):
        _compose_hive_runtime_from_catalog_snapshot(
            config,
            drifted,
            repository_roots={},
            state_root=tmp_path / "state",
            expected_catalog_digest=snapshot.digest,
        )
    for invalid in (
        b"sha256:" + b"a" * 64,
        object(),
        "sha256:" + "a" * 63,
        "SHA256:" + "a" * 64,
        "sha256:" + "A" * 64,
    ):
        with pytest.raises(HiveRuntimeError, match="catalog_digest_mismatch"):
            _compose_hive_runtime_from_catalog_snapshot(
                config,
                snapshot,
                repository_roots={},
                state_root=tmp_path / "state",
                expected_catalog_digest=invalid,
            )


def test_snapshot_composer_rejects_invalid_snapshot_without_public_secret(tmp_path: Path) -> None:
    marker = "catalog-payload-class-member-principal-repo-home-session-journal-path-secret"

    with pytest.raises(HiveRuntimeError) as raised:
        _compose_hive_runtime_from_catalog_snapshot(
            marker,
            marker,
            repository_roots={},
            state_root=tmp_path / "state",
        )

    assert str(raised.value) == "invalid_catalog_snapshot"
    rendered = "".join(traceback.format_exception(raised.value))
    assert marker not in rendered


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
