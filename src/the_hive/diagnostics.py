"""Canonical, redacted DiagnosticV2 value and wire contract."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import json
import re
from types import MappingProxyType


class DiagnosticSeverityV2(StrEnum):
    """The complete set of DiagnosticV2 severities."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


_TOKEN_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
_SENSITIVE_TOKEN_PATTERN = re.compile(
    r"(?:traceback|stacktrace|exception)|(?:^|[_.-])(?:sk|pk|api|key|token|secret)[_-]?[A-Za-z0-9]{8,}$|^AKIA[A-Z0-9]{16}$",
    re.IGNORECASE,
)
_MAX_TOKEN_BYTES = 128
_MAX_CAUSES = 8
_MAX_WIRE_BYTES = 4096
_WIRE_KEYS = (
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


def _invalid() -> None:
    raise ValueError("invalid DiagnosticV2 value")


def _validate_token(value: object, *, sensitive: bool = True) -> str:
    if type(value) is not str:
        _invalid()
    if len(value.encode("utf-8")) > _MAX_TOKEN_BYTES:
        _invalid()
    if _TOKEN_PATTERN.fullmatch(value) is None:
        _invalid()
    if sensitive and _SENSITIVE_TOKEN_PATTERN.search(value) is not None:
        _invalid()
    return value


@dataclass(frozen=True, slots=True)
class DiagnosticCodeSpecV2:
    """An immutable code membership record without policy defaults."""

    code: str

    def __post_init__(self) -> None:
        _validate_token(self.code, sensitive=False)


DIAGNOSTIC_CODE_SPECS_V2 = MappingProxyType(
    {
        code: DiagnosticCodeSpecV2(code)
        for code in (
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
        )
    }
)


def _validate_registered_code(value: object) -> str:
    code = _validate_token(value, sensitive=False)
    if code not in DIAGNOSTIC_CODE_SPECS_V2:
        _invalid()
    return code


def _validate_retry(retryable: object, retry_after_seconds: object) -> None:
    if type(retryable) is not bool:
        _invalid()
    if retry_after_seconds is None:
        return
    if not retryable or type(retry_after_seconds) is not int:
        _invalid()
    if not 1 <= retry_after_seconds <= 86400:
        _invalid()


def _validate_choices(
    fallback_applied: object,
    requested_choice: object,
    effective_choice: object,
) -> None:
    if type(fallback_applied) is not bool:
        _invalid()
    if requested_choice is None or effective_choice is None:
        if requested_choice is not None or effective_choice is not None or fallback_applied:
            _invalid()
        return
    requested = _validate_token(requested_choice)
    effective = _validate_token(effective_choice)
    if fallback_applied is not (requested != effective):
        _invalid()


def _validate_causes(code: str, causes: object) -> tuple[str, ...]:
    if type(causes) is not tuple or len(causes) > _MAX_CAUSES:
        _invalid()
    validated = tuple(_validate_registered_code(cause) for cause in causes)
    if len(set(validated)) != len(validated):
        _invalid()
    if code in validated:
        _invalid()
    return validated


def _validate_value(
    *,
    code: object,
    severity: object,
    retryable: object,
    retry_after_seconds: object,
    fallback_applied: object,
    requested_choice: object,
    effective_choice: object,
    action: object,
    causes: object,
    legacy_code: object,
) -> None:
    checked_code = _validate_registered_code(code)
    if type(severity) is not DiagnosticSeverityV2:
        _invalid()
    _validate_retry(retryable, retry_after_seconds)
    _validate_choices(fallback_applied, requested_choice, effective_choice)
    _validate_token(action)
    _validate_causes(checked_code, causes)
    if legacy_code is not None:
        _invalid()


@dataclass(frozen=True, slots=True)
class DiagnosticV2:
    """A fully validated, redacted DiagnosticV2 value."""

    code: str
    severity: DiagnosticSeverityV2
    retryable: bool
    retry_after_seconds: int | None
    fallback_applied: bool
    requested_choice: str | None
    effective_choice: str | None
    action: str
    causes: tuple[str, ...]
    legacy_code: None

    def __post_init__(self) -> None:
        _validate_value(
            code=self.code,
            severity=self.severity,
            retryable=self.retryable,
            retry_after_seconds=self.retry_after_seconds,
            fallback_applied=self.fallback_applied,
            requested_choice=self.requested_choice,
            effective_choice=self.effective_choice,
            action=self.action,
            causes=self.causes,
            legacy_code=self.legacy_code,
        )


def diagnostic_for(
    code: str,
    *,
    severity: DiagnosticSeverityV2,
    retryable: bool,
    retry_after_seconds: int | None,
    fallback_applied: bool,
    requested_choice: str | None,
    effective_choice: str | None,
    action: str,
    causes: tuple[str, ...],
) -> DiagnosticV2:
    """Create one validated DiagnosticV2 without adding policy defaults."""

    return DiagnosticV2(
        code=code,
        severity=severity,
        retryable=retryable,
        retry_after_seconds=retry_after_seconds,
        fallback_applied=fallback_applied,
        requested_choice=requested_choice,
        effective_choice=effective_choice,
        action=action,
        causes=causes,
        legacy_code=None,
    )


def _canonical_json_bytes(value: dict[str, object]) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _validate_wire_size(value: dict[str, object]) -> None:
    try:
        wire_bytes = _canonical_json_bytes(value)
    except (OverflowError, RecursionError, TypeError, ValueError):
        _invalid()
    if len(wire_bytes) > _MAX_WIRE_BYTES:
        _invalid()


def serialize_diagnostic_v2(value: DiagnosticV2) -> dict[str, object]:
    """Return the exact, ordered, deterministic DiagnosticV2 wire dictionary."""

    if type(value) is not DiagnosticV2:
        _invalid()
    _validate_value(
        code=value.code,
        severity=value.severity,
        retryable=value.retryable,
        retry_after_seconds=value.retry_after_seconds,
        fallback_applied=value.fallback_applied,
        requested_choice=value.requested_choice,
        effective_choice=value.effective_choice,
        action=value.action,
        causes=value.causes,
        legacy_code=value.legacy_code,
    )
    wire: dict[str, object] = {
        "schema_version": 2,
        "code": value.code,
        "severity": value.severity.value,
        "retryable": value.retryable,
        "retry_after_seconds": value.retry_after_seconds,
        "fallback_applied": value.fallback_applied,
        "requested_choice": value.requested_choice,
        "effective_choice": value.effective_choice,
        "action": value.action,
        "causes": list(value.causes),
        "legacy_code": None,
    }
    _validate_wire_size(wire)
    return wire


def parse_diagnostic_v2(value: object) -> DiagnosticV2:
    """Parse only the exact canonical DiagnosticV2 wire dictionary."""

    if type(value) is not dict or tuple(value) != _WIRE_KEYS:
        _invalid()
    if type(value["schema_version"]) is not int or value["schema_version"] != 2:
        _invalid()
    if type(value["severity"]) is not str:
        _invalid()
    if type(value["causes"]) is not list:
        _invalid()
    _validate_wire_size(value)
    try:
        severity = DiagnosticSeverityV2(value["severity"])
    except ValueError:
        _invalid()
    return DiagnosticV2(
        code=value["code"],
        severity=severity,
        retryable=value["retryable"],
        retry_after_seconds=value["retry_after_seconds"],
        fallback_applied=value["fallback_applied"],
        requested_choice=value["requested_choice"],
        effective_choice=value["effective_choice"],
        action=value["action"],
        causes=tuple(value["causes"]),
        legacy_code=value["legacy_code"],
    )
