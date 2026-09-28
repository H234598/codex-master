from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from the_hive import fleet_markdown, hive_policy
from the_hive.fleet_registry import AgentDescriptor, Provider, RunnerKind
from the_hive.runtime_migration_policy import (
    RUNTIME_MIGRATION_POLICY_PATH,
    RuntimeMigrationPolicyError,
    load_runtime_migration_policy,
    render_runtime_migration_policy_block,
    validate_runtime_migration_policy_materialization,
)


_COMMON_POLICY_PATH = Path("src/the_hive/markdown/common.md")


def _canonical_source(payload: object) -> bytes:
    return (
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _write_policy_variant(
    tmp_path: Path,
    mutate: object,
) -> Path:
    payload = json.loads(RUNTIME_MIGRATION_POLICY_PATH.read_text(encoding="utf-8"))
    assert callable(mutate)
    mutate(payload)
    path = tmp_path / "runtime-migration-policy-v1.json"
    path.write_bytes(_canonical_source(payload))
    return path


def _group(payload: dict[str, object], identifier: str) -> dict[str, object]:
    rule_groups = payload["rule_groups"]
    assert type(rule_groups) is list
    for group in rule_groups:
        assert type(group) is dict
        if group["id"] == identifier:
            return group
    raise AssertionError(f"missing group {identifier}")


def _rule(payload: dict[str, object], identifier: str) -> dict[str, object]:
    rule_groups = payload["rule_groups"]
    assert type(rule_groups) is list
    for group in rule_groups:
        assert type(group) is dict
        rules = group["rules"]
        assert type(rules) is list
        for rule in rules:
            assert type(rule) is dict
            if rule["id"] == identifier:
                return rule
    raise AssertionError(f"missing rule {identifier}")


def _agent(runner: RunnerKind) -> AgentDescriptor:
    provider = (
        Provider.GEMINI_API
        if runner is RunnerKind.GEMINI_CLI
        else Provider.OPENAI_CHATGPT
    )
    return AgentDescriptor(
        agent_id="a1",
        series_prefix="a",
        ordinal=1,
        label="Agentin A1",
        runner=runner,
        provider=provider,
        model="test-model",
        account_id=None,
        home=Path("/unused/a1"),
        session="agent-a1",
        enabled=True,
        skill_profile="worker",
    )


def test_loads_the_complete_canonical_runtime_migration_policy() -> None:
    source_bytes = RUNTIME_MIGRATION_POLICY_PATH.read_bytes()

    contract = load_runtime_migration_policy()

    assert contract.version == 1
    assert contract.source_bytes == source_bytes
    assert contract.source_digest == "sha256:" + hashlib.sha256(source_bytes).hexdigest()
    assert [group.identifier for group in contract.rule_groups] == [
        "delivery-and-preflight",
        "versioning-and-deterministic-execution",
        "transaction-publication-and-recovery",
        "failure-observation-and-retention",
        "evidence-contracts-and-telemetry",
    ]
    assert sum(len(group.rules) for group in contract.rule_groups) == 35
    assert {
        rule.enforcement for group in contract.rule_groups for rule in group.rules
    } == {"machine", "governance"}
    contracts = {group.identifier: group.machine_contract for group in contract.rule_groups}
    assert contracts["delivery-and-preflight"]["feature_delivery"] == "separate"
    compatibility = contracts["versioning-and-deterministic-execution"][
        "compatibility"
    ]
    journal = contracts["transaction-publication-and-recovery"]["journal"]
    telemetry = contracts["evidence-contracts-and-telemetry"]["telemetry"]
    assert compatibility == {
        "attested_predecessor_count": 1,
        "current_version_required": True,
        "support_window_versions": 2,
        "unbounded_legacy": "deny",
    }
    assert journal["rollback_guard"] == "cas_fencing"
    assert journal["max_bytes"] == 8 * 1024 * 1024
    assert telemetry["retention_seconds"] == 30 * 24 * 60 * 60


def test_rendered_block_is_exactly_materialized_in_common_policy() -> None:
    common_bytes = _COMMON_POLICY_PATH.read_bytes()
    contract = load_runtime_migration_policy()
    rendered = render_runtime_migration_policy_block(contract)

    assert validate_runtime_migration_policy_materialization(common_bytes) == contract
    assert common_bytes.count(rendered) == 1
    assert f'source_digest":"{contract.source_digest}"'.encode() in rendered
    assert b"normierten Maschinenvertr\xc3\xa4ge" in rendered
    assert b"Runtime-Executor f\xc3\xbcr die operative Ausf\xc3\xbchrung ist unbekannt" in rendered
    assert b'"rollback_guard":"cas_fencing"' in rendered


@pytest.mark.parametrize(
    ("mutate", "error"),
    [
        (
            lambda payload: _rule(
                payload, "explicit-versioned-stepwise-migrators"
            ).pop("enforcement"),
            "runtime_migration_policy_rule_invalid",
        ),
        (
            lambda payload: _rule(
                payload, "explicit-versioned-stepwise-migrators"
            ).__setitem__("enforcement", "governance"),
            "runtime_migration_policy_rule_catalog_invalid",
        ),
        (
            lambda payload: _rule(
                payload, "bounded-compatibility-window"
            ).__setitem__("requirement", "Legacy fallback ist erlaubt."),
            "runtime_migration_policy_compatibility_invalid",
        ),
        (
            lambda payload: _group(
                payload, "transaction-publication-and-recovery"
            ).pop("machine_contract"),
            "runtime_migration_policy_rule_group_invalid",
        ),
        (
            lambda payload: _group(
                payload, "versioning-and-deterministic-execution"
            )["machine_contract"]["compatibility"].__setitem__(
                "unbounded_legacy", "allow"
            ),
            "runtime_migration_policy_machine_contract_invalid",
        ),
        (
            lambda payload: _group(
                payload, "failure-observation-and-retention"
            )["machine_contract"].__setitem__("observation_timeout_seconds", 0),
            "runtime_migration_policy_machine_contract_value_invalid",
        ),
    ],
    ids=(
        "missing-machine-field",
        "incorrect-machine-field",
        "legacy-fallback",
        "missing-machine-contract",
        "unsafe-legacy-enum",
        "unbounded-observation-timeout",
    ),
)
def test_rejects_incomplete_or_unsafe_runtime_migration_policy_source(
    tmp_path: Path,
    mutate: object,
    error: str,
) -> None:
    path = _write_policy_variant(tmp_path, mutate)

    with pytest.raises(RuntimeMigrationPolicyError, match=error):
        load_runtime_migration_policy(path)


def test_rejects_stale_digest_and_drifted_rendered_block() -> None:
    common_bytes = _COMMON_POLICY_PATH.read_bytes()
    contract = load_runtime_migration_policy()
    stale_digest = b"sha256:" + b"0" * 64
    assert stale_digest.decode() != contract.source_digest
    wrong_digest = common_bytes.replace(
        contract.source_digest.encode("ascii"), stale_digest, 1
    )
    drifted_block = common_bytes.replace(
        b"Install, Migrate, Activate und Rollback", b"Install, Update, Activate und Rollback", 1
    )

    with pytest.raises(
        RuntimeMigrationPolicyError,
        match="runtime_migration_policy_block_digest_stale",
    ):
        validate_runtime_migration_policy_materialization(wrong_digest)
    with pytest.raises(
        RuntimeMigrationPolicyError,
        match="runtime_migration_policy_block_stale",
    ):
        validate_runtime_migration_policy_materialization(drifted_block)


def test_source_change_requires_an_exactly_refreshed_common_policy_block(
    tmp_path: Path,
) -> None:
    def change_rationale(payload: dict[str, object]) -> None:
        rule_groups = payload["rule_groups"]
        assert type(rule_groups) is list
        first_group = rule_groups[0]
        assert type(first_group) is dict
        first_group["rationale"] += " Zusätzlich attestiert."

    changed_source = _write_policy_variant(tmp_path, change_rationale)

    with pytest.raises(
        RuntimeMigrationPolicyError,
        match="runtime_migration_policy_block_digest_stale",
    ):
        validate_runtime_migration_policy_materialization(
            _COMMON_POLICY_PATH.read_bytes(),
            policy_path=changed_source,
        )


def test_common_policy_loader_fails_closed_when_default_materialization_is_invalid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_closed(_: bytes) -> object:
        raise RuntimeMigrationPolicyError("runtime_migration_policy_block_stale")

    monkeypatch.setattr(
        hive_policy,
        "validate_runtime_migration_policy_materialization",
        fail_closed,
    )

    with pytest.raises(
        hive_policy.CommonPolicyError,
        match="runtime_migration_policy_block_stale",
    ):
        hive_policy.load_common_policy()


def test_runtime_migration_block_projects_to_every_provider_home() -> None:
    common_bytes = _COMMON_POLICY_PATH.read_bytes()
    for runner in (RunnerKind.CODEX_CLI, RunnerKind.GEMINI_CLI):
        projection = fleet_markdown.fleet_markdown_projection(_agent(runner))
        primary = projection.artifacts[projection.metadata.provider_artifact_name]

        assert primary.startswith(common_bytes)
        assert validate_runtime_migration_policy_materialization(
            primary[: len(common_bytes)]
        ).source_digest == load_runtime_migration_policy().source_digest
