from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
import traceback

import pytest

from codex_master.hive.config import load_agent_class_catalog, load_agent_class_catalog_snapshot, load_hive_config
from codex_master.hive.events import HiveEventStore
from codex_master.hive.runtime import (
    HiveRuntimeError,
    HiveRuntimeEvidence,
    _compose_hive_runtime_from_catalog_snapshot,
    build_hive_runtime,
    enforced_pilot_gate,
    read_hive_runtime_evidence,
)
from codex_master.hive.repositories import RepositoryRegistry
from codex_master.server import AgentError, build_server_admission_runtime
from codex_master.usage_snapshot import (
    AccountUsageEvidenceV2,
    TrackerEvidenceV2,
    UsageEvidenceV2,
    UsageLimitV2,
    UsageTrendV2,
)
import codex_master.hive.runtime as hive_runtime


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


def test_runtime_evidence_is_read_only_and_data_sparse_when_state_is_missing(tmp_path: Path) -> None:
    catalog = ROOT / "codex-agent-classes.json"
    config = ROOT / "codex-hive.json"
    state_root = tmp_path / "state"

    evidence = read_hive_runtime_evidence(
        catalog_path=catalog,
        config_path=config,
        state_root=state_root,
        now=lambda: NOW,
    )

    assert evidence.public() == {
        "schema_version": 1,
        "mode": "shadow",
        "config_digest": evidence.config_digest,
        "catalog_digest": evidence.catalog_digest,
        "repository": "not_configured",
        "principal": "not_configured",
        "authority": "fail_closed",
        "state": "not_configured",
        "pilot": "blocked",
        "reason_codes": ["repository_not_configured", "principal_not_configured", "state_not_configured"],
        "mutation_performed": False,
        "raw_output": "not_returned",
    }
    assert not state_root.exists()


def test_runtime_evidence_returns_schema_complete_fail_closed_dto_for_bad_inputs(tmp_path: Path) -> None:
    catalog = ROOT / "codex-agent-classes.json"
    config = ROOT / "codex-hive.json"

    for kwargs, reason in (
        ({"state_root": Path("relative-state")}, "hive_runtime_unavailable"),
        ({"config_path": tmp_path / "missing-config.json"}, "hive_config_unavailable"),
        ({"catalog_path": object()}, "hive_runtime_unavailable"),
        ({"config_path": object()}, "hive_runtime_unavailable"),
        ({"state_root": object()}, "hive_runtime_unavailable"),
    ):
        evidence = read_hive_runtime_evidence(
            catalog_path=kwargs.get("catalog_path", catalog),
            config_path=kwargs.get("config_path", config),
            state_root=kwargs.get("state_root", tmp_path / "state"),
            now=lambda: NOW,
        )
        assert isinstance(evidence, HiveRuntimeEvidence)
        public = evidence.public()
        assert public["schema_version"] == 1
        assert public["reason_codes"] == [reason]
        assert public["mutation_performed"] is False
        assert set(public) == {
            "schema_version",
            "mode",
            "config_digest",
            "catalog_digest",
            "repository",
            "principal",
            "authority",
            "state",
            "pilot",
            "reason_codes",
            "mutation_performed",
            "raw_output",
        }


def test_runtime_evidence_reuses_read_only_assembled_runtime_without_materializing_state(tmp_path: Path) -> None:
    classes, config = config_bundle()
    roots = {"repo-one": repo(tmp_path)}
    state_root = tmp_path / "state"
    build_hive_runtime(
        config,
        classes,
        repository_roots=roots,
        state_root=state_root,
        materialize_principals=True,
        now=lambda: NOW,
    )
    before = (state_root / "principals.json").read_bytes()

    evidence = read_hive_runtime_evidence(
        catalog_path=ROOT / "tests/fixtures/hive/classes-valid.json",
        config_path=ROOT / "tests/fixtures/hive/hive-enforced-valid.json",
        state_root=state_root,
        repository_roots=roots,
        now=lambda: NOW,
    )

    assert evidence.public()["repository"] == "ready"
    assert evidence.public()["principal"] == "ready"
    assert evidence.public()["authority"] == "fail_closed"
    assert evidence.public()["state"] == "ready"
    assert evidence.public()["mutation_performed"] is False
    assert (state_root / "principals.json").read_bytes() == before


def test_runtime_evidence_fails_closed_for_untrusted_principal_state(tmp_path: Path) -> None:
    classes, config = config_bundle()
    roots = {"repo-one": repo(tmp_path)}
    state_root = tmp_path / "state"
    build_hive_runtime(
        config,
        classes,
        repository_roots=roots,
        state_root=state_root,
        materialize_principals=True,
        now=lambda: NOW,
    )
    principal_state = state_root / "principals.json"
    principal_state.chmod(0o644)

    evidence = read_hive_runtime_evidence(
        catalog_path=ROOT / "tests/fixtures/hive/classes-valid.json",
        config_path=ROOT / "tests/fixtures/hive/hive-enforced-valid.json",
        state_root=state_root,
        repository_roots=roots,
        now=lambda: NOW,
    )

    assert evidence.authority == "fail_closed"
    assert evidence.principal == "invalid"
    assert evidence.state == "ready"
    assert evidence.mutation_performed is False
    assert "hive_runtime_invalid" in evidence.reason_codes


def test_runtime_evidence_does_not_treat_unlocked_state_directory_as_ready(tmp_path: Path) -> None:
    state_root = tmp_path / "state"
    state_root.mkdir(mode=0o700)
    evidence = read_hive_runtime_evidence(
        catalog_path=ROOT / "codex-agent-classes.json",
        config_path=ROOT / "codex-hive.json",
        state_root=state_root,
        now=lambda: NOW,
    )
    assert evidence.state == "unavailable"
    assert evidence.authority == "fail_closed"
    assert evidence.mutation_performed is False


def _attested_usage_evidence(*, now: datetime, status: str = "complete") -> UsageEvidenceV2:
    generation = "attested-generation"
    return UsageEvidenceV2(
        accounts=(
            AccountUsageEvidenceV2(
                "attested-pool",
                (UsageLimitV2("main", 18000, generation, 0.0, 100.0, now + timedelta(hours=1)),),
                (
                    UsageTrendV2(
                        "main",
                        18000,
                        generation,
                        "complete",
                        now,
                        now + timedelta(hours=1),
                    ),
                ),
                (TrackerEvidenceV2("main", 18000, generation, "complete", now),),
            ),
        ),
        status=status,  # type: ignore[arg-type]
        captured_at=now,
        generated_at=now,
    )


def test_enforced_pilot_gate_requires_an_attested_pool_reader_not_a_dynamic_mapping(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classes, source_config = config_bundle()
    classes = {
        **classes,
        "koenigin": replace(
            classes["koenigin"],
            public_lifecycle="persistent",
            allowed_lifecycles=("persistent",),
            allowed_model_families=("sol",),
            min_reasoning="max",
            max_reasoning="max",
        ),
    }
    config = replace(
        source_config,
        mode="enforced",
        repositories=(
            {
                "repo_id": "codex-master",
                "remote_identity": "https://github.com/H234598/codex-master.git",
                "default_branch": "main",
                "config_digest": "sha256:" + "a" * 64,
            },
        ),
        principals=(
            {"principal_id": "godbee-main", "class_id": "gottbiene", "parent_principal_id": None, "repo_id": None},
            {"principal_id": "queen-codex-master", "class_id": "koenigin", "parent_principal_id": "godbee-main", "repo_id": "codex-master"},
        ),
    )

    monkeypatch.setattr(
        hive_runtime,
        "read_usage_evidence_v2",
        lambda *, clock: _attested_usage_evidence(now=NOW),
    )

    assert enforced_pilot_gate(config, classes, {"fresh": True, "model_family": "sol", "reasoning": "max", "long_lived": True}) == {
        "allowed": False,
        "reason_code": "pilot_account_attestation_invalid",
        "raw_output": "not_returned",
    }
    ready = enforced_pilot_gate(config, classes, now=lambda: NOW)
    assert ready == {"allowed": True, "reason_code": "pilot_ready", "raw_output": "not_returned"}
    monkeypatch.setattr(
        hive_runtime,
        "read_usage_evidence_v2",
        lambda *, clock: _attested_usage_evidence(now=NOW, status="stale"),
    )
    assert enforced_pilot_gate(config, classes, now=lambda: NOW) == {
        "allowed": False,
        "reason_code": "pilot_account_attestation_invalid",
        "raw_output": "not_returned",
    }
    monkeypatch.setattr(hive_runtime, "read_usage_evidence_v2", lambda *, clock: {"issuer": "unknown"})
    assert enforced_pilot_gate(config, classes, now=lambda: NOW) == {
        "allowed": False,
        "reason_code": "pilot_account_attestation_invalid",
        "raw_output": "not_returned",
    }
