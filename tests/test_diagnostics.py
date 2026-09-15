"""Contract tests for the canonical, value-only DiagnosticV2 owner."""

from __future__ import annotations

import ast
import json
from dataclasses import FrozenInstanceError
from pathlib import Path
from types import MappingProxyType

import pytest

from the_hive import diagnostics
from the_hive.diagnostics import (
    DIAGNOSTIC_CODE_SPECS_V2,
    DiagnosticCodeSpecV2,
    DiagnosticSeverityV2,
    DiagnosticV2,
    diagnostic_for,
    parse_diagnostic_v2,
    serialize_diagnostic_v2,
)


PLAN_08_CODES = frozenset(
    {
        "resolver.request_invalid",
        "resolver.class_unknown",
        "resolver.class_unavailable",
        "resolver.lifecycle_unknown",
        "resolver.lifecycle_forbidden",
        "resolver.provider_unknown",
        "resolver.provider_forbidden",
        "resolver.model_unknown",
        "resolver.model_unavailable",
        "resolver.reasoning_unknown",
        "resolver.reasoning_forbidden",
        "resolver.ultra_forbidden",
        "resolver.capability_floor_unmet",
        "resolver.capability_target_clamped",
        "resolver.no_eligible_candidate",
        "resolver.offer_generation_stale",
        "resolver.offer_expired",
        "resolver.explicit_choice_replaced",
        "resolver.fallback_applied",
        "resolver.class_dormant",
        "resolver.direct_spawn_forbidden",
        "resolver.promotion_requirements_unmet",
        "resolver.promotion_upgrade_unavailable",
        "resolver.promotion_state_conflict",
        "resolver.leadership_provider_forbidden",
        "resolver.series_capability_changed",
        "resolver.task_complexity_uncertain",
        "authority.principal_unattested",
        "authority.parent_mismatch",
        "authority.repo_scope_denied",
        "authority.delegation_forbidden",
        "authority.role_transition_denied",
        "authority.queen_boundary_violation",
        "authority.global_scope_required",
        "tool.contract_unavailable",
        "tool.not_allowed",
        "tool.transport_unavailable",
        "tool.version_mismatch",
        "tool.call_invalid",
        "tool.result_contract_invalid",
        "skill.required_missing",
        "skill.request_denied",
        "skill.catalog_unavailable",
        "skill.reference_unknown",
        "skill.provider_adapter_missing",
        "skill.manifest_stale",
        "skill.request_pending",
        "skill.grant_exceeds_authority",
        "skill.scope_expansion_forbidden",
        "skill.materialization_failed",
        "skill.reload_required",
        "skill.restart_failed",
        "credential.source_unavailable",
        "credential.source_unsafe",
        "credential.parse_invalid",
        "credential.section_unknown",
        "credential.slot_empty",
        "credential.secret_duplicate",
        "credential.secret_invalid",
        "credential.source_missing_grace",
        "credential.account_disabled",
        "provider.unavailable",
        "provider.probe_stale",
        "provider.probe_failed",
        "provider.model_at_capacity",
        "provider.model_catalog_stale",
        "provider.tooling_insufficient",
        "quota.account_exhausted",
        "quota.model_window_exhausted",
        "quota.weekly_budget_low",
        "quota.reset_unknown",
        "quota.request_lease_conflict",
        "quota.billing_guard_reached",
        "quota.probe_budget_exhausted",
        "quota.provider_share_reserved",
        "account.openai_usage_tier_changed",
        "credit.policy_forbidden",
        "credit.limit_reached",
        "credit.snapshot_stale",
        "credit.only_worker_mode",
        "credit.only_model_forbidden",
        "credit.reservation_conflict",
        "pricing.generation_stale",
        "pricing.model_price_unknown",
        "pricing.source_conflict",
        "admission.denied",
        "admission.interactive_hold",
        "admission.reservation_conflict",
        "admission.reservation_stale",
        "admission.local_lane_blocked",
        "admission.ollama_burst_headroom_insufficient",
        "admission.ollama_hard_cap_reached",
        "resource.snapshot_stale",
        "resource.snapshot_invalid",
        "resource.monitor_unavailable",
        "resource.session_metrics_unavailable",
        "resource.hive_io_pressure",
        "resource.target_device_io_pressure",
        "resource.gpu_dock_lane_pressure",
        "resource.cpu_pressure",
        "resource.memory_pressure",
        "resource.thermal_pressure",
        "resource.swap_thrash",
        "resource.gpu_memory_insufficient",
        "resource.device_mapping_unknown",
        "resource.cgroup_unavailable",
        "resource.history_insufficient",
        "resource.reservation_estimate_missing",
        "lifecycle.agent_not_ready",
        "lifecycle.agent_already_running",
        "lifecycle.start_failed",
        "lifecycle.stop_failed",
        "lifecycle.input_not_ready",
        "lifecycle.context_handoff_failed",
        "lease.conflict",
        "lease.expired",
        "lease.recovery_forbidden",
        "assignment.scope_overlap",
        "assignment.write_scope_denied",
        "assignment.dependency_blocked",
        "assignment.report_timeout",
        "assignment.integration_pending",
        "research.mode_unavailable",
        "research.native_backend_unavailable",
        "research.fallback_disallowed",
        "research.source_coverage_insufficient",
        "research.citation_validation_failed",
        "research.web_access_unavailable",
        "research.cost_guard_reached",
        "research.provider_rate_limited",
        "plan.source_hash_mismatch",
        "plan.status_conflict",
        "plan.destination_conflict",
        "plan.refile_ambiguous",
        "plan.queen_unresolved",
        "plan.central_plan_write_forbidden",
        "plan.completion_evidence_missing",
        "plan.manifest_stale",
        "plan.orphan_detected",
        "plan.live_evidence_missing",
        "registry.generation_conflict",
        "registry.reload_failed",
        "deployment.dirty_worktree",
        "deployment.tests_failed",
        "deployment.install_failed",
        "deployment.namespace_unavailable",
        "deployment.plugin_cache_stale",
        "deployment.live_smoke_failed",
        "deployment.rollback_failed",
    }
)

D129_BUS_CODES = frozenset(
    {
        "BUS_E_STORE_ROOT_UNTRUSTED",
        "BUS_E_STORE_FILE_UNTRUSTED",
        "BUS_E_STORE_SCHEMA_TOO_OLD",
        "BUS_E_STORE_SCHEMA_TOO_NEW",
        "BUS_E_STORE_SCHEMA_UNKNOWN",
        "BUS_E_STORE_INTEGRITY",
        "BUS_E_PARTITION_SEQ_CONFLICT",
        "BUS_E_EFFECT_CONFLICT",
        "BUS_E_SCHEMA",
        "BUS_E_CANONICALIZATION",
        "BUS_E_TOPIC_INVALID",
        "BUS_E_EVENT_TOO_LARGE",
        "BUS_E_SECRET_CLASSIFICATION",
        "BUS_E_ACL_DENIED",
        "BUS_E_REPO_SCOPE",
        "BUS_E_IDEMPOTENCY_CONFLICT",
        "BUS_E_PRODUCER_SEQ_GAP",
        "BUS_E_PRODUCER_SEQ_REGRESSION",
        "BUS_E_PAYLOAD_DIGEST",
        "BUS_E_PAYLOAD_MISSING",
        "BUS_E_CURSOR_GAP",
        "BUS_E_SUBSCRIPTION_STALE",
        "BUS_E_RETENTION_PRECONDITION",
        "BUS_E_SNAPSHOT_TOO_LARGE",
        "BUS_E_ARCHIVE_EVIDENCE_MISSING",
        "BUS_E_STORE_OWNER_ACTIVE",
        "BUS_E_STORE_BUSY",
        "BUS_E_DELIVERY_LEASE_ACTIVE",
        "BUS_E_DELIVERY_BACKOFF",
        "BUS_E_BACKPRESSURE",
        "BUS_W_BACKPRESSURE_75",
        "BUS_W_CHECKPOINT_INCOMPLETE",
    }
)

EXPECTED_CODES = PLAN_08_CODES | D129_BUS_CODES
WIRE_KEYS = (
    "schema_version",
    "code",
    "severity",
    "retryable",
    "retry_after_seconds",
    "fallback_applied",
    "requested_choice",
    "effective_choice",
    "action",
    "causes",
    "legacy_code",
)


def make_diagnostic(**changes: object) -> DiagnosticV2:
    values: dict[str, object] = {
        "code": "resolver.request_invalid",
        "severity": DiagnosticSeverityV2.ERROR,
        "retryable": False,
        "retry_after_seconds": None,
        "fallback_applied": False,
        "requested_choice": None,
        "effective_choice": None,
        "action": "retry_request",
        "causes": (),
    }
    values.update(changes)
    return diagnostic_for(**values)  # type: ignore[arg-type]


def make_wire(**changes: object) -> dict[str, object]:
    wire: dict[str, object] = serialize_diagnostic_v2(make_diagnostic())
    wire.update(changes)
    return wire


def test_severity_is_closed_and_code_specs_are_immutable_membership_only() -> None:
    assert tuple(DiagnosticSeverityV2) == (
        DiagnosticSeverityV2.INFO,
        DiagnosticSeverityV2.WARNING,
        DiagnosticSeverityV2.ERROR,
        DiagnosticSeverityV2.CRITICAL,
    )
    assert [member.value for member in DiagnosticSeverityV2] == [
        "info",
        "warning",
        "error",
        "critical",
    ]
    with pytest.raises(ValueError):
        DiagnosticSeverityV2("debug")

    assert isinstance(DIAGNOSTIC_CODE_SPECS_V2, MappingProxyType)
    assert set(DIAGNOSTIC_CODE_SPECS_V2) == EXPECTED_CODES
    assert all(
        isinstance(spec, DiagnosticCodeSpecV2) and spec.code == code
        for code, spec in DIAGNOSTIC_CODE_SPECS_V2.items()
    )
    with pytest.raises(TypeError):
        DIAGNOSTIC_CODE_SPECS_V2["new.code"] = DiagnosticCodeSpecV2("new.code")  # type: ignore[index]
    with pytest.raises(FrozenInstanceError):
        next(iter(DIAGNOSTIC_CODE_SPECS_V2.values())).code = "other.code"  # type: ignore[misc]
    assert DiagnosticCodeSpecV2.__slots__ == ("code",)
    assert not hasattr(next(iter(DIAGNOSTIC_CODE_SPECS_V2.values())), "retryable")


def test_diagnostic_for_validates_and_produces_a_frozen_slotted_value() -> None:
    value = make_diagnostic(
        code="BUS_E_STORE_BUSY",
        severity=DiagnosticSeverityV2.WARNING,
        retryable=True,
        retry_after_seconds=60,
        fallback_applied=True,
        requested_choice="primary_model",
        effective_choice="fallback_model",
        action="retry_later",
        causes=("BUS_E_BACKPRESSURE",),
    )

    assert value == DiagnosticV2(
        code="BUS_E_STORE_BUSY",
        severity=DiagnosticSeverityV2.WARNING,
        retryable=True,
        retry_after_seconds=60,
        fallback_applied=True,
        requested_choice="primary_model",
        effective_choice="fallback_model",
        action="retry_later",
        causes=("BUS_E_BACKPRESSURE",),
        legacy_code=None,
    )
    assert DiagnosticV2.__slots__ == (
        "code",
        "severity",
        "retryable",
        "retry_after_seconds",
        "fallback_applied",
        "requested_choice",
        "effective_choice",
        "action",
        "causes",
        "legacy_code",
    )
    with pytest.raises(FrozenInstanceError):
        value.action = "other_action"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("code", "unknown.code"),
        ("code", "resolver/request_invalid"),
        ("code", 1),
        ("severity", "error"),
        ("severity", 3),
        ("retryable", 1),
        ("fallback_applied", 0),
        ("action", "plain text"),
        ("action", "https://example.invalid"),
        ("action", "/tmp/problem"),
        ("action", "person@example.invalid"),
        ("action", "AKIAABCDEFGHIJKLMNOP"),
        ("action", "Traceback"),
        ("action", "x" * 129),
        ("requested_choice", "choice\nvalue"),
        ("effective_choice", "choice\x00value"),
        ("causes", ["resolver.class_unknown"]),
    ],
)
def test_diagnostic_for_rejects_bad_types_unsafe_tokens_and_unknown_codes(
    field: str, bad_value: object
) -> None:
    with pytest.raises(ValueError):
        make_diagnostic(**{field: bad_value})


@pytest.mark.parametrize(
    "changes",
    [
        {"retryable": False, "retry_after_seconds": 1},
        {"retryable": True, "retry_after_seconds": False},
        {"retryable": True, "retry_after_seconds": 0},
        {"retryable": True, "retry_after_seconds": 86401},
        {"retryable": True, "retry_after_seconds": 1.0},
    ],
)
def test_retry_delay_is_optional_but_only_valid_for_retryable_values(
    changes: dict[str, object]
) -> None:
    with pytest.raises(ValueError):
        make_diagnostic(**changes)


def test_retry_delay_bounds_accept_builtin_int_endpoints_only() -> None:
    assert make_diagnostic(retryable=True, retry_after_seconds=1).retry_after_seconds == 1
    assert (
        make_diagnostic(retryable=True, retry_after_seconds=86400).retry_after_seconds
        == 86400
    )
    assert make_diagnostic(retryable=True, retry_after_seconds=None).retry_after_seconds is None


@pytest.mark.parametrize(
    "changes",
    [
        {"requested_choice": "requested", "effective_choice": None},
        {"requested_choice": None, "effective_choice": "effective"},
        {
            "requested_choice": "requested",
            "effective_choice": "effective",
            "fallback_applied": False,
        },
        {
            "requested_choice": "same",
            "effective_choice": "same",
            "fallback_applied": True,
        },
        {"requested_choice": None, "effective_choice": None, "fallback_applied": True},
    ],
)
def test_choice_pair_and_fallback_are_exactly_consistent(
    changes: dict[str, object]
) -> None:
    with pytest.raises(ValueError):
        make_diagnostic(**changes)


def test_equal_choices_without_fallback_are_valid() -> None:
    value = make_diagnostic(
        requested_choice="selected_model",
        effective_choice="selected_model",
        fallback_applied=False,
    )
    assert value.requested_choice == value.effective_choice == "selected_model"


@pytest.mark.parametrize(
    "causes",
    [
        tuple("resolver.class_unknown" for _ in range(2)),
        ("resolver.request_invalid",),
        ("unknown.code",),
        tuple("resolver.class_unknown" for _ in range(9)),
        ("resolver.class_unknown", 7),
        (["resolver.class_unknown"],),
    ],
)
def test_causes_are_registered_unique_nonself_and_bounded(causes: tuple[object, ...]) -> None:
    with pytest.raises(ValueError):
        make_diagnostic(causes=causes)


def test_eight_unique_registered_causes_are_valid() -> None:
    causes = tuple(sorted(EXPECTED_CODES - {"resolver.request_invalid"}))[:8]
    value = make_diagnostic(causes=causes)
    assert value.causes == causes


def test_serializer_has_the_exact_canonical_wire_order_and_is_deterministic() -> None:
    value = make_diagnostic(
        retryable=True,
        retry_after_seconds=1,
        requested_choice="preferred",
        effective_choice="fallback",
        fallback_applied=True,
        causes=("resolver.class_unknown",),
    )
    first = serialize_diagnostic_v2(value)
    second = serialize_diagnostic_v2(value)

    assert tuple(first) == WIRE_KEYS
    assert first == second
    assert first == {
        "schema_version": 2,
        "code": "resolver.request_invalid",
        "severity": "error",
        "retryable": True,
        "retry_after_seconds": 1,
        "fallback_applied": True,
        "requested_choice": "preferred",
        "effective_choice": "fallback",
        "action": "retry_request",
        "causes": ["resolver.class_unknown"],
        "legacy_code": None,
    }
    assert len(json.dumps(first, ensure_ascii=False, separators=(",", ":")).encode()) <= 4096


def test_parse_and_serialize_round_trip_exactly() -> None:
    value = make_diagnostic(
        code="BUS_W_CHECKPOINT_INCOMPLETE",
        severity=DiagnosticSeverityV2.WARNING,
        retryable=True,
        retry_after_seconds=86400,
        causes=("BUS_E_BACKPRESSURE",),
    )
    assert parse_diagnostic_v2(serialize_diagnostic_v2(value)) == value


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("schema_version", True),
        ("schema_version", 2.0),
        ("schema_version", 1),
        ("code", "unknown.code"),
        ("code", 3),
        ("code", object()),
        ("severity", "debug"),
        ("severity", DiagnosticSeverityV2.ERROR),
        ("retryable", 1),
        ("retry_after_seconds", True),
        ("fallback_applied", 0),
        ("requested_choice", "free text"),
        ("effective_choice", "https://example.invalid"),
        ("action", "value\x1fhere"),
        ("causes", ("resolver.class_unknown",)),
        ("legacy_code", "class_not_available"),
    ],
)
def test_parser_rejects_wrong_builtin_types_and_invalid_values(
    field: str, bad_value: object
) -> None:
    with pytest.raises(ValueError):
        parse_diagnostic_v2(make_wire(**{field: bad_value}))


@pytest.mark.parametrize(
    "changes",
    [
        {"retryable": False, "retry_after_seconds": 1},
        {"retryable": True, "retry_after_seconds": 0},
        {"requested_choice": "one", "effective_choice": None},
        {"requested_choice": "one", "effective_choice": "two", "fallback_applied": False},
        {"causes": ["resolver.request_invalid"]},
        {"causes": ["resolver.class_unknown"] * 9},
        {"causes": ["unknown.code"]},
        {"causes": ["resolver.request_invalid"]},
    ],
)
def test_parser_rejects_cross_field_and_cause_violations(
    changes: dict[str, object]
) -> None:
    with pytest.raises(ValueError):
        parse_diagnostic_v2(make_wire(**changes))


def test_parser_rejects_missing_extra_and_noncanonical_field_order() -> None:
    wire = make_wire()
    missing = dict(wire)
    del missing["legacy_code"]
    with pytest.raises(ValueError):
        parse_diagnostic_v2(missing)

    extra = dict(wire)
    extra["detail"] = "not_allowed"
    with pytest.raises(ValueError):
        parse_diagnostic_v2(extra)

    reordered = {"code": wire["code"], **{key: value for key, value in wire.items() if key != "code"}}
    with pytest.raises(ValueError):
        parse_diagnostic_v2(reordered)


def test_large_wire_candidate_and_non_diagnostic_serialization_fail_closed() -> None:
    oversized = make_wire(action="x" * 4097)
    with pytest.raises(ValueError):
        diagnostics._validate_wire_size(oversized)
    with pytest.raises(ValueError):
        parse_diagnostic_v2(oversized)
    with pytest.raises(ValueError):
        serialize_diagnostic_v2(object())  # type: ignore[arg-type]


def test_module_is_stdlib_only_and_has_no_forbidden_owner_imports() -> None:
    source = Path(diagnostics.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = [
        node.module or ""
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    ] + [alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names]

    forbidden = ("admin", "fleet", "server", "runtime", "bus", "s2", "authority", "codex_master")
    assert not any(
        any(part in imported.lower() for part in forbidden) for imported in imports
    )
