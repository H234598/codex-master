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


_COMMON_POLICY_PATH = hive_policy.COMMON_POLICY_PATH


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
        "diagnostic-evidence-and-remediation-gates",
    ]
    assert sum(len(group.rules) for group in contract.rule_groups) == 50
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
    diagnostic = contracts["diagnostic-evidence-and-remediation-gates"]
    assert compatibility == {
        "attested_predecessor_count": 1,
        "current_version_required": True,
        "support_window_versions": 2,
        "unbounded_legacy": "deny",
    }
    assert journal["rollback_guard"] == "cas_fencing"
    assert journal["max_bytes"] == 8 * 1024 * 1024
    assert telemetry["retention_seconds"] == 30 * 24 * 60 * 60
    assert diagnostic == {
        "baselines": {
            "claim_without_prebaseline": "deny",
            "post_baseline": "required",
            "pre_baseline": "immutable_redacted_required",
            "quiescence": "required",
        },
        "canary": {
            "canonical_artifact_mutation": "deny",
            "first_failed_layer": "stop",
            "layers": [
                "manager_syntax_transport",
                "namespace_sandbox",
                "helper",
                "product_logic",
            ],
        },
        "classifier": {
            "contract": "versioned_closed",
            "generic_after_improved_classification_limit": 2,
            "negative_matrix": "complete_pre_live_supported_families",
            "unknown": "fail_closed",
        },
        "cleanup": {
            "foreign_object_mutation": "deny",
            "fresh_owner_check": "required",
            "result_precedence": "cleanup",
        },
        "diagnostic_gates": {
            "activation": "separate_remediation_gate",
            "diagnostic": "separate",
            "root_cause_for_product_activation": "required",
        },
        "evidence_freshness": {
            "cutover": "fresh_ttl_only",
            "stale": "block",
            "ttl_declaration": "required",
        },
        "fixture_gate": {
            "activation_and_cutover": "required",
            "policy_and_diagnostic_integration": "not_required",
        },
        "harness_scope": {
            "bound_declarations": [
                "files",
                "production_loc",
                "error_families",
                "live_attempts",
            ],
            "exceedance": {
                "design_review": "required",
                "native_alternative": "required",
                "silent_growth": "deny",
            },
        },
        "live_attempts": {
            "blind_identical_retry": "deny",
            "maximum": 1,
            "per": "evidence_changing_reviewed_commit",
        },
        "migration_decision": {
            "full_rebuild": "requires_minimal_fix_comparison_and_justification",
            "minimal_fix": "preferred_when_root_cause_closed",
        },
        "phases": {"gated": ["install", "activate", "observe", "commit"]},
        "post_blind_diagnostic_revision": {"limit": 2, "next": "hold"},
        "pre_generation_compatibility": {
            "before": ["generate", "mutation"],
            "dimensions": ["manager", "runtime", "client", "features"],
            "matrix": "required",
        },
        "telemetry": {
            "activation_authority": "deny",
            "before_root_cause": "reviewed_bounded_secret_free_observability_only",
            "second_authority": "deny",
        },
    }


def test_rendered_block_is_exactly_materialized_in_common_policy() -> None:
    common_bytes = _COMMON_POLICY_PATH.read_bytes()
    contract = load_runtime_migration_policy()
    rendered = render_runtime_migration_policy_block(contract)

    assert validate_runtime_migration_policy_materialization(common_bytes) == contract
    assert common_bytes.count(rendered) == 1
    assert f'source_digest":"{contract.source_digest}"'.encode() in rendered
    assert b"normierten Maschinenvertr\xc3\xa4ge" in rendered
    assert b"Policy-Executor f\xc3\xbcr die operative Durchsetzung dieser Vertr\xc3\xa4ge ist unbekannt" in rendered
    assert b"keine Aussage \xc3\xbcber vorhandene Runtime-Mechanismen" in rendered
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


@pytest.mark.parametrize(
    ("mutate", "error"),
    [
        (
            lambda payload: _group(
                payload, "diagnostic-evidence-and-remediation-gates"
            )["machine_contract"]["diagnostic_gates"].pop("root_cause_for_product_activation"),
            "runtime_migration_policy_machine_contract_invalid",
        ),
        (
            lambda payload: _group(
                payload, "diagnostic-evidence-and-remediation-gates"
            )["machine_contract"]["telemetry"].__setitem__(
                "second_authority", "allow"
            ),
            "runtime_migration_policy_machine_contract_invalid",
        ),
        (
            lambda payload: _group(
                payload, "diagnostic-evidence-and-remediation-gates"
            )["machine_contract"]["live_attempts"].__setitem__("maximum", 2),
            "runtime_migration_policy_machine_contract_value_invalid",
        ),
        (
            lambda payload: _group(
                payload, "diagnostic-evidence-and-remediation-gates"
            )["machine_contract"]["classifier"].__setitem__("unknown", "allow"),
            "runtime_migration_policy_machine_contract_invalid",
        ),
        (
            lambda payload: _group(
                payload, "diagnostic-evidence-and-remediation-gates"
            )["machine_contract"]["classifier"].__setitem__(
                "generic_after_improved_classification_limit", 3
            ),
            "runtime_migration_policy_machine_contract_value_invalid",
        ),
        (
            lambda payload: _group(
                payload, "diagnostic-evidence-and-remediation-gates"
            )["machine_contract"]["canary"].__setitem__(
                "layers", [
                    "namespace_sandbox",
                    "manager_syntax_transport",
                    "helper",
                    "product_logic",
                ]
            ),
            "runtime_migration_policy_machine_contract_invalid",
        ),
        (
            lambda payload: _group(
                payload, "diagnostic-evidence-and-remediation-gates"
            )["machine_contract"]["canary"].__setitem__(
                "canonical_artifact_mutation", "allow"
            ),
            "runtime_migration_policy_machine_contract_invalid",
        ),
        (
            lambda payload: _group(
                payload, "diagnostic-evidence-and-remediation-gates"
            )["machine_contract"]["baselines"].__setitem__(
                "claim_without_prebaseline", "allow"
            ),
            "runtime_migration_policy_machine_contract_invalid",
        ),
        (
            lambda payload: _group(
                payload, "diagnostic-evidence-and-remediation-gates"
            )["machine_contract"]["cleanup"].__setitem__(
                "foreign_object_mutation", "allow"
            ),
            "runtime_migration_policy_machine_contract_invalid",
        ),
        (
            lambda payload: _group(
                payload, "diagnostic-evidence-and-remediation-gates"
            )["machine_contract"]["fixture_gate"].__setitem__(
                "policy_and_diagnostic_integration", "required"
            ),
            "runtime_migration_policy_machine_contract_invalid",
        ),
        (
            lambda payload: _group(
                payload, "diagnostic-evidence-and-remediation-gates"
            )["machine_contract"]["evidence_freshness"].__setitem__(
                "stale", "allow"
            ),
            "runtime_migration_policy_machine_contract_invalid",
        ),
        (
            lambda payload: _group(
                payload, "diagnostic-evidence-and-remediation-gates"
            )["machine_contract"]["harness_scope"].__setitem__(
                "bound_declarations", [
                    "files",
                    "production_loc",
                    "error_families",
                ]
            ),
            "runtime_migration_policy_machine_contract_invalid",
        ),
        (
            lambda payload: _group(
                payload, "diagnostic-evidence-and-remediation-gates"
            )["machine_contract"]["phases"].__setitem__(
                "gated", ["install", "observe", "activate", "commit"]
            ),
            "runtime_migration_policy_machine_contract_invalid",
        ),
        (
            lambda payload: _group(
                payload, "diagnostic-evidence-and-remediation-gates"
            )["machine_contract"]["migration_decision"].__setitem__(
                "minimal_fix", "optional"
            ),
            "runtime_migration_policy_machine_contract_invalid",
        ),
        (
            lambda payload: _group(
                payload, "diagnostic-evidence-and-remediation-gates"
            )["machine_contract"]["post_blind_diagnostic_revision"].__setitem__(
                "limit", 3
            ),
            "runtime_migration_policy_machine_contract_value_invalid",
        ),
        (
            lambda payload: _group(
                payload, "diagnostic-evidence-and-remediation-gates"
            )["machine_contract"]["pre_generation_compatibility"].__setitem__(
                "before", ["mutation"]
            ),
            "runtime_migration_policy_machine_contract_invalid",
        ),
        (
            lambda payload: _group(
                payload, "diagnostic-evidence-and-remediation-gates"
            )["rules"].pop(),
            "runtime_migration_policy_rule_catalog_invalid",
        ),
    ],
    ids=(
        "missing-root-cause-activation-gate",
        "telemetry-cannot-be-second-authority",
        "one-live-attempt-bound",
        "unknown-classification-fails-closed",
        "generic-results-stop-after-two",
        "canary-layer-order",
        "canary-cannot-mutate-canonical-artifacts",
        "prebaseline-required-for-unchanged-claim",
        "cleanup-cannot-mutate-foreign-objects",
        "fixture-cycle-is-forbidden",
        "stale-evidence-cannot-open-cutover",
        "harness-bounds-must-be-declared",
        "phase-order-is-gated",
        "minimal-fix-comparison-is-required",
        "blind-diagnostic-revision-limit",
        "compatibility-matrix-before-generation-and-mutation",
        "complete-atomic-rule-catalog",
    ),
)
def test_rejects_unsafe_diagnostic_evidence_and_remediation_contract(
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
