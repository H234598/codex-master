"""Canonical, technology-neutral Runtime and release migration policy.

This module validates only the policy source and its rendered Common-Policy
projection.  It deliberately does not claim that a concrete runtime executor
already implements the declared machine-enforcement rules.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from types import MappingProxyType


RUNTIME_MIGRATION_POLICY_PATH = (
    Path(__file__).with_name("markdown") / "runtime-migration-policy-v1.json"
)
MAX_RUNTIME_MIGRATION_POLICY_BYTES = 48 * 1024

_FORMAT = "runtime-migration-policy-v1"
_VERSION = 1
_IDENTIFIER_RE = re.compile(r"[a-z][a-z0-9-]{0,95}\Z")
_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_BEGIN_PREFIX = b"<!-- hive-runtime-migration-policy-v1:begin "
_BEGIN_SUFFIX = b" -->"
_END_MARKER = b"<!-- hive-runtime-migration-policy-v1:end -->"
_COMPATIBILITY_REQUIRED_TERMS = (
    "aktuelle",
    "genau eine",
    "attestierte Vorgängerversion",
    "unbeschränkte",
    "implizite Legacy-Kompatibilität",
    "verboten",
)
_EXPECTED_MACHINE_CONTRACTS: dict[str, dict[str, object]] = {
    "delivery-and-preflight": {
        "cutover_preflight": "read_only_live",
        "development_preflight": "read_only_live",
        "feature_delivery": "separate",
        "migration_budget": "separate_prerequisite",
        "migration_delivery": "separate_prerequisite",
        "scope_gate": "explicit",
    },
    "versioning-and-deterministic-execution": {
        "bundle": {
            "implicit_path_dependency": "deny",
            "interactive_shell_dependency": "deny",
            "worktree_dependency": "deny",
        },
        "compatibility": {
            "attested_predecessor_count": 1,
            "current_version_required": True,
            "support_window_versions": 2,
            "unbounded_legacy": "deny",
        },
        "downlevel": {"mode": "reject", "offline_staged_path": "required"},
        "dry_run": {
            "actions": True,
            "bound_inputs": True,
            "cutover_rebind": "cas_fencing",
            "digests": True,
            "rollback": True,
            "target_identity": True,
        },
        "idempotence": "required",
        "lifecycle_phases": ["install", "migrate", "activate", "rollback"],
        "migrator_edge": "runtime-vN-to-vN-plus-1",
        "provenance": "attested_before_publish",
    },
    "transaction-publication-and-recovery": {
        "crash_recovery": "durable_resume_or_hold",
        "install_activate": "separate",
        "journal": {
            "allowlist": True,
            "durability": "fsync",
            "max_bytes": 8 * 1024 * 1024,
            "redaction_test": True,
            "rollback_guard": "cas_fencing",
            "rollback_order": "inverse",
            "snapshot_kinds": ["pointer", "file", "service_unit", "state"],
            "storage_failure": "block_publish",
        },
        "lock": {"fencing": True, "owner": "single", "transaction_id": "monotone"},
        "operator_abort": {"after": "hold", "auto_rollback_max": 1},
        "owner_mode_drift": "revalidate_before_mutation_and_publish",
        "publish_before_activate": True,
        "replay": {"plan_digest": True, "transaction_fence": True},
    },
    "failure-observation-and-retention": {
        "after_auto_rollback": "hold",
        "attested_lease": "monotone_or_attested",
        "identical_live_failure_limit": 2,
        "irreversible": {
            "mode": "forward_only",
            "pre_snapshot": True,
            "tested_roll_forward": True,
        },
        "new_cause_evidence": True,
        "observation_timeout_seconds": 60 * 60,
        "regression_test": True,
        "remote_partition": "bounded_retry_or_hold",
        "retention": {
            "gc_after": "confirmed_consumer_switch_and_observation",
            "security_denylist": "immediate_exception",
        },
    },
    "evidence-contracts-and-telemetry": {
        "compiler": {
            "artifact_digest": True,
            "canonical_source": True,
            "staleness_test": True,
        },
        "consumer_contracts": {
            "classes": [
                "launcher",
                "hook",
                "protocol_endpoint",
                "service_unit",
                "stable_name",
            ],
            "real_e2e_minimum": 1,
        },
        "crash_faultpoint": "after_each_mutating_phase",
        "error_classes": {
            "deterministic": "policy_or_schema",
            "retry_mode": "bounded",
            "retryable": "infrastructure",
        },
        "fixture": {
            "digest": True,
            "periodic_structure_compare": True,
            "source": "redacted_real_live",
        },
        "snapshot": {
            "allowlist": True,
            "max_bytes": 8 * 1024 * 1024,
            "redaction_test": True,
            "secret_free": True,
        },
        "telemetry": {
            "bounded_fields": True,
            "fields": [
                "duration",
                "phase",
                "transaction_id",
                "failure_class",
                "rollback",
                "final_identity",
            ],
            "fixed_schema": True,
            "retention_seconds": 30 * 24 * 60 * 60,
            "secret_free": True,
        },
    },
    "diagnostic-evidence-and-remediation-gates": {
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
    },
}

_EXPECTED_RULE_GROUPS = (
    (
        "delivery-and-preflight",
        (
            ("separate-feature-and-migration-deliverables", "governance"),
            ("read-only-live-preflight-before-development-and-cutover", "governance"),
            ("migration-budget-gate", "governance"),
            ("scope-multiplication-gate", "governance"),
        ),
    ),
    (
        "versioning-and-deterministic-execution",
        (
            ("explicit-versioned-stepwise-migrators", "machine"),
            ("bounded-compatibility-window", "machine"),
            ("downlevel-refusal-and-offline-staged-path", "machine"),
            ("deterministic-dry-run-and-cutover-rebind", "machine"),
            ("idempotent-lifecycle-phases", "machine"),
            ("staged-provenance-before-publish", "machine"),
            ("self-contained-release-bundle", "machine"),
        ),
    ),
    (
        "transaction-publication-and-recovery",
        (
            ("complete-snapshot-journal-and-inverse-fenced-rollback", "machine"),
            ("atomic-publication-before-consumer-activation", "machine"),
            ("install-separate-from-activate", "machine"),
            ("single-owner-monotone-transaction-fencing", "machine"),
            ("replay-fence-and-plan-digest", "machine"),
            ("durable-crash-resume-or-hold", "machine"),
            ("operator-abort-one-rollback-then-hold", "machine"),
            ("storage-fsync-failure-blocks-publish", "machine"),
            ("owner-and-mode-drift-revalidation", "machine"),
        ),
    ),
    (
        "failure-observation-and-retention",
        (
            ("two-identical-live-failures-require-new-evidence", "machine"),
            ("bounded-observation-one-auto-rollback-then-hold", "machine"),
            ("irreversible-forward-only-roll-forward", "machine"),
            ("deferred-gc-with-security-denylist-exception", "machine"),
            ("bounded-remote-partition-handling", "machine"),
            ("monotone-time-and-attested-lease", "machine"),
            ("attested-host-version-preflight", "machine"),
        ),
    ),
    (
        "evidence-contracts-and-telemetry",
        (
            ("redacted-live-fixture-digest-and-periodic-structure-compare", "machine"),
            ("snapshot-allowlist-redaction-and-size-limit", "machine"),
            ("crash-faultpoint-after-each-mutating-phase", "machine"),
            ("consumer-contracts-with-real-end-to-end", "machine"),
            ("focused-tests-before-independent-review", "governance"),
            ("bounded-secret-free-migration-telemetry", "machine"),
            ("failure-classification-retry-policy-schema", "machine"),
            ("canonical-policy-source-artifact-digest-staleness", "machine"),
        ),
    ),
    (
        "diagnostic-evidence-and-remediation-gates",
        (
            ("separate-diagnostic-and-remediation-activation-gates", "machine"),
            ("reviewed-observability-only-telemetry-before-root-cause", "machine"),
            ("one-canary-attempt-per-evidence-changing-reviewed-commit", "machine"),
            ("generic-results-stop-harness-expansion", "machine"),
            ("declared-diagnostic-harness-scope-budget", "machine"),
            (
                "versioned-closed-classifier-negative-matrix-and-fail-closed-unknown",
                "machine",
            ),
            ("layered-canary-first-failure-stops", "machine"),
            ("immutable-prebaseline-postbaseline-and-quiescence", "machine"),
            ("cleanup-precedence-and-foreign-object-protection", "machine"),
            ("fixture-required-for-activation-not-policy-integration", "machine"),
            ("fresh-evidence-ttl-cutover-gate", "machine"),
            ("gated-install-activate-observe-commit-phases", "machine"),
            ("minimal-fix-comparison-before-runtime-rebuild", "machine"),
            ("two-blind-diagnostic-revisions-then-hold", "machine"),
            ("compatibility-matrix-before-generate-or-mutate", "machine"),
        ),
    ),
)


class RuntimeMigrationPolicyError(ValueError):
    """The versioned runtime-migration policy source or projection is invalid."""


@dataclass(frozen=True, slots=True)
class RuntimeMigrationRule:
    """One named policy rule, classified by its intended enforcement surface."""

    identifier: str
    enforcement: str
    requirement: str


@dataclass(frozen=True, slots=True)
class RuntimeMigrationRuleGroup:
    """A human-readable rationale and its complete set of named rules."""

    identifier: str
    machine_contract: Mapping[str, object]
    rationale: str
    rules: tuple[RuntimeMigrationRule, ...]


@dataclass(frozen=True, slots=True)
class RuntimeMigrationPolicyContract:
    """A strictly validated canonical source with its deterministic digest."""

    version: int
    source_bytes: bytes
    source_digest: str
    rule_groups: tuple[RuntimeMigrationRuleGroup, ...]


def _read_bounded(path: Path) -> bytes:
    try:
        with path.open("rb") as policy_file:
            value = policy_file.read(MAX_RUNTIME_MIGRATION_POLICY_BYTES + 1)
    except OSError as exc:
        raise RuntimeMigrationPolicyError("runtime_migration_policy_unavailable") from exc
    if len(value) > MAX_RUNTIME_MIGRATION_POLICY_BYTES:
        raise RuntimeMigrationPolicyError("runtime_migration_policy_oversized")
    return value


def _reject_duplicate_object(pairs: list[tuple[object, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise RuntimeMigrationPolicyError("runtime_migration_policy_json_invalid")
        result[key] = value
    return result


def _reject_json_constant(_: str) -> object:
    raise RuntimeMigrationPolicyError("runtime_migration_policy_json_invalid")


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
            + b"\n"
        )
    except (TypeError, ValueError) as exc:
        raise RuntimeMigrationPolicyError("runtime_migration_policy_json_invalid") from exc


def _strict_text(value: object, code: str, maximum: int) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > maximum
        or any(ord(character) < 32 for character in value)
    ):
        raise RuntimeMigrationPolicyError(code)
    return value


def _parse_rule(value: object) -> RuntimeMigrationRule:
    if type(value) is not dict or set(value) != {"enforcement", "id", "requirement"}:
        raise RuntimeMigrationPolicyError("runtime_migration_policy_rule_invalid")
    identifier = _strict_text(value["id"], "runtime_migration_policy_rule_invalid", 96)
    enforcement = _strict_text(
        value["enforcement"], "runtime_migration_policy_rule_invalid", 16
    )
    requirement = _strict_text(
        value["requirement"], "runtime_migration_policy_rule_invalid", 2048
    )
    if _IDENTIFIER_RE.fullmatch(identifier) is None or enforcement not in {
        "machine",
        "governance",
    }:
        raise RuntimeMigrationPolicyError("runtime_migration_policy_rule_invalid")
    return RuntimeMigrationRule(identifier, enforcement, requirement)


def _strict_contract_value(observed: object, expected: object) -> bool:
    if type(observed) is not type(expected):
        return False
    if type(expected) is dict:
        return (
            set(observed) == set(expected)
            and all(
                _strict_contract_value(observed[key], expected[key])
                for key in expected
            )
        )
    if type(expected) is list:
        return len(observed) == len(expected) and all(
            _strict_contract_value(actual, required)
            for actual, required in zip(observed, expected, strict=True)
        )
    return observed == expected


def _machine_contract_shape(observed: object, expected: object) -> bool:
    if type(observed) is not type(expected):
        return False
    if type(expected) is dict:
        return set(observed) == set(expected) and all(
            _machine_contract_shape(observed[key], expected[key]) for key in expected
        )
    if type(expected) is list:
        return len(observed) == len(expected) and all(
            _machine_contract_shape(actual, required)
            for actual, required in zip(observed, expected, strict=True)
        )
    return True


def _validate_machine_contract_bounds(
    identifier: str,
    machine_contract: dict[str, object],
) -> None:
    try:
        if identifier == "transaction-publication-and-recovery":
            journal = machine_contract["journal"]
            assert type(journal) is dict
            values = (journal["max_bytes"],)
            bounds = ((1024, 64 * 1024 * 1024),)
        elif identifier == "failure-observation-and-retention":
            values = (
                machine_contract["identical_live_failure_limit"],
                machine_contract["observation_timeout_seconds"],
            )
            bounds = ((1, 2), (1, 24 * 60 * 60))
        elif identifier == "evidence-contracts-and-telemetry":
            consumer_contracts = machine_contract["consumer_contracts"]
            snapshot = machine_contract["snapshot"]
            telemetry = machine_contract["telemetry"]
            assert type(consumer_contracts) is dict
            assert type(snapshot) is dict
            assert type(telemetry) is dict
            values = (
                consumer_contracts["real_e2e_minimum"],
                snapshot["max_bytes"],
                telemetry["retention_seconds"],
            )
            bounds = ((1, 64), (1024, 64 * 1024 * 1024), (1, 366 * 24 * 60 * 60))
        elif identifier == "diagnostic-evidence-and-remediation-gates":
            classifier = machine_contract["classifier"]
            live_attempts = machine_contract["live_attempts"]
            blind_revisions = machine_contract["post_blind_diagnostic_revision"]
            assert type(classifier) is dict
            assert type(live_attempts) is dict
            assert type(blind_revisions) is dict
            values = (
                classifier["generic_after_improved_classification_limit"],
                live_attempts["maximum"],
                blind_revisions["limit"],
            )
            bounds = ((1, 2), (1, 1), (1, 2))
        else:
            return
    except (AssertionError, KeyError) as exc:
        raise RuntimeMigrationPolicyError(
            "runtime_migration_policy_machine_contract_invalid"
        ) from exc
    for value, (minimum, maximum) in zip(values, bounds, strict=True):
        if type(value) is not int or not minimum <= value <= maximum:
            raise RuntimeMigrationPolicyError(
                "runtime_migration_policy_machine_contract_value_invalid"
            )


def _parse_machine_contract(identifier: str, value: object) -> Mapping[str, object]:
    if type(value) is not dict:
        raise RuntimeMigrationPolicyError("runtime_migration_policy_machine_contract_invalid")
    expected = _EXPECTED_MACHINE_CONTRACTS.get(identifier)
    if expected is None or not _machine_contract_shape(value, expected):
        raise RuntimeMigrationPolicyError("runtime_migration_policy_machine_contract_invalid")
    _validate_machine_contract_bounds(identifier, value)
    if not _strict_contract_value(value, expected):
        raise RuntimeMigrationPolicyError("runtime_migration_policy_machine_contract_invalid")
    return MappingProxyType(dict(value))


def _parse_rule_group(value: object) -> RuntimeMigrationRuleGroup:
    if type(value) is not dict or set(value) != {
        "id",
        "machine_contract",
        "rationale",
        "rules",
    }:
        raise RuntimeMigrationPolicyError("runtime_migration_policy_rule_group_invalid")
    identifier = _strict_text(
        value["id"], "runtime_migration_policy_rule_group_invalid", 96
    )
    rationale = _strict_text(
        value["rationale"], "runtime_migration_policy_rule_group_invalid", 1024
    )
    raw_rules = value["rules"]
    if (
        _IDENTIFIER_RE.fullmatch(identifier) is None
        or type(raw_rules) is not list
        or not raw_rules
        or len(raw_rules) > 64
    ):
        raise RuntimeMigrationPolicyError("runtime_migration_policy_rule_group_invalid")
    rules = tuple(_parse_rule(raw_rule) for raw_rule in raw_rules)
    if len({rule.identifier for rule in rules}) != len(rules):
        raise RuntimeMigrationPolicyError("runtime_migration_policy_rule_group_invalid")
    machine_contract = _parse_machine_contract(identifier, value["machine_contract"])
    return RuntimeMigrationRuleGroup(identifier, machine_contract, rationale, rules)


def _validate_required_rule_catalog(
    groups: tuple[RuntimeMigrationRuleGroup, ...],
) -> None:
    observed = tuple(
        (
            group.identifier,
            tuple((rule.identifier, rule.enforcement) for rule in group.rules),
        )
        for group in groups
    )
    if observed != _EXPECTED_RULE_GROUPS:
        raise RuntimeMigrationPolicyError("runtime_migration_policy_rule_catalog_invalid")
    compatibility_rule = next(
        rule
        for group in groups
        for rule in group.rules
        if rule.identifier == "bounded-compatibility-window"
    )
    if any(term not in compatibility_rule.requirement for term in _COMPATIBILITY_REQUIRED_TERMS):
        raise RuntimeMigrationPolicyError("runtime_migration_policy_compatibility_invalid")


def load_runtime_migration_policy(
    path: str | Path = RUNTIME_MIGRATION_POLICY_PATH,
) -> RuntimeMigrationPolicyContract:
    """Load one canonical, bounded and complete migration-policy source."""

    source_bytes = _read_bounded(Path(path))
    try:
        source = json.loads(
            source_bytes.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_object,
            parse_constant=_reject_json_constant,
        )
    except RuntimeMigrationPolicyError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise RuntimeMigrationPolicyError("runtime_migration_policy_json_invalid") from exc
    if type(source) is not dict or set(source) != {"format", "rule_groups", "version"}:
        raise RuntimeMigrationPolicyError("runtime_migration_policy_fields_invalid")
    if source_bytes != _canonical_json_bytes(source):
        raise RuntimeMigrationPolicyError("runtime_migration_policy_noncanonical")
    if source["format"] != _FORMAT or type(source["version"]) is not int:
        raise RuntimeMigrationPolicyError("runtime_migration_policy_version_invalid")
    if source["version"] != _VERSION:
        raise RuntimeMigrationPolicyError("runtime_migration_policy_version_unsupported")
    raw_groups = source["rule_groups"]
    if type(raw_groups) is not list or not raw_groups or len(raw_groups) > 16:
        raise RuntimeMigrationPolicyError("runtime_migration_policy_rule_groups_invalid")
    rule_groups = tuple(_parse_rule_group(raw_group) for raw_group in raw_groups)
    if len({group.identifier for group in rule_groups}) != len(rule_groups):
        raise RuntimeMigrationPolicyError("runtime_migration_policy_rule_groups_invalid")
    _validate_required_rule_catalog(rule_groups)
    return RuntimeMigrationPolicyContract(
        version=_VERSION,
        source_bytes=source_bytes,
        source_digest="sha256:" + hashlib.sha256(source_bytes).hexdigest(),
        rule_groups=rule_groups,
    )


def _marker_bytes(contract: RuntimeMigrationPolicyContract) -> bytes:
    metadata = {"source_digest": contract.source_digest, "version": contract.version}
    return (
        _BEGIN_PREFIX
        + json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode("ascii")
        + _BEGIN_SUFFIX
    )


def render_runtime_migration_policy_block(
    contract: RuntimeMigrationPolicyContract,
) -> bytes:
    """Render the complete, deterministic Common-Policy block for one source."""

    if (
        not isinstance(contract, RuntimeMigrationPolicyContract)
        or contract.version != _VERSION
        or _SHA256_RE.fullmatch(contract.source_digest) is None
    ):
        raise RuntimeMigrationPolicyError("runtime_migration_policy_contract_invalid")
    lines = [
        _marker_bytes(contract).decode("ascii"),
        "## Hive Runtime- und Release-Migrationspolicy v1",
        "",
        "Diese versionierte Policy ist technologie-neutral. `enforcement: machine` "
        "kennzeichnet einen verbindlichen, maschinenprüfbaren Laufzeit- oder "
        "Releasevertrag. Dieser Policy-Compiler erzwingt derzeit ausschließlich "
        "die kanonische Quelle, die normierten Maschinenverträge und ihre "
        "vollständige Projektion; ein Policy-Executor für die operative "
        "Durchsetzung dieser Verträge ist unbekannt und nicht implementiert. "
        "Daraus folgt keine Aussage über vorhandene Runtime-Mechanismen. "
        "`enforcement: governance` kennzeichnet einen verbindlichen "
        "menschlichen Prozess-Gate.",
        "",
        "Kanonische Quelle: `src/the_hive/markdown/runtime-migration-policy-v1.json`.",
        "",
    ]
    for group in contract.rule_groups:
        machine_contract = json.dumps(
            dict(group.machine_contract),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        lines.extend(
            (
                f"### {group.identifier}",
                "",
                group.rationale,
                "",
                "Maschinenvertrag (nur Source-/Compiler-Durchsetzung): "
                f"`{machine_contract}`",
                "",
            )
        )
        for rule in group.rules:
            lines.append(
                f"- `{rule.identifier}` (enforcement: {rule.enforcement}): "
                f"{rule.requirement}"
            )
        lines.append("")
    lines.extend((_END_MARKER.decode("ascii"), ""))
    return "\n".join(lines).encode("utf-8")


def validate_runtime_migration_policy_materialization(
    common_bytes: bytes,
    *,
    policy_path: str | Path = RUNTIME_MIGRATION_POLICY_PATH,
) -> RuntimeMigrationPolicyContract:
    """Fail closed unless Common Policy carries exactly the current render."""

    if type(common_bytes) is not bytes:
        raise RuntimeMigrationPolicyError("runtime_migration_policy_common_invalid")
    contract = load_runtime_migration_policy(policy_path)
    expected = render_runtime_migration_policy_block(contract)
    expected_begin = _marker_bytes(contract)
    if common_bytes.count(_BEGIN_PREFIX) != 1 or common_bytes.count(_END_MARKER) != 1:
        raise RuntimeMigrationPolicyError("runtime_migration_policy_block_missing_or_duplicated")
    begin = common_bytes.find(_BEGIN_PREFIX)
    end = common_bytes.find(_END_MARKER, begin)
    if begin < 0 or end < begin:
        raise RuntimeMigrationPolicyError("runtime_migration_policy_block_missing_or_duplicated")
    actual = common_bytes[begin : end + len(_END_MARKER)]
    if not actual.startswith(expected_begin):
        raise RuntimeMigrationPolicyError("runtime_migration_policy_block_digest_stale")
    if actual + b"\n" != expected:
        raise RuntimeMigrationPolicyError("runtime_migration_policy_block_stale")
    return contract


__all__ = [
    "MAX_RUNTIME_MIGRATION_POLICY_BYTES",
    "RUNTIME_MIGRATION_POLICY_PATH",
    "RuntimeMigrationPolicyContract",
    "RuntimeMigrationPolicyError",
    "RuntimeMigrationRule",
    "RuntimeMigrationRuleGroup",
    "load_runtime_migration_policy",
    "render_runtime_migration_policy_block",
    "validate_runtime_migration_policy_materialization",
]
