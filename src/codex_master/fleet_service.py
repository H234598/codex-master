from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field, replace as dataclass_replace
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import ContextManager, Mapping, TypeVar, cast

from .fleet_registry import (
    FleetAccount,
    FleetAccountV2,
    FleetSeries,
    FleetSnapshot,
    FleetSnapshotV2,
    InventorySnapshot,
    LimitState,
    Provider,
    SecretState,
    build_inventory,
    fleet_document,
    mark_account_limit,
    normalize_fleet_document,
    plan_account_delete,
    plan_account_upsert,
    public_fleet_snapshot,
)
from .fleet_runners import (
    FleetRunnerError,
    ProbeDiagnosticCode,
    ProbeEndpointRole,
    ProbeHttpClass,
    ProbeOutputShape,
    ProbeStdoutEventClass,
    ProbeStdoutShape,
    ProbeProcessPhase,
    ProviderErrorQuotaObservation,
    ProbeResult,
    normalize_gemini_probe_diagnostic_code,
    normalize_gemini_probe_output_shape,
    normalize_gemini_probe_stdout_event_class,
    normalize_gemini_probe_stdout_shape,
    normalize_gemini_probe_process_phase,
    validate_gemini_probe_model,
)
from .selection import (
    FairnessLedger,
    ModelRole,
    SelectionCandidate,
    SelectionPolicy,
    TaskKind,
    preview_selection,
)
from .ollama_host_transport import CONTROL_HOST_REF
from .admin_contracts import OperationV1
from .agent_contracts import AgentReceiptV1, remote_envelope_digest, serialize_agent_result
from .agent_operations import AgentOperationError, AgentOperationStore
from .agent_operations import AgentPrincipalV1 as OperationAgentPrincipalV1
from .hive.state import HiveStateError, HiveStateStore
from .ollama_registry import (
    OllamaInstanceV1,
    OllamaModelV1,
    OllamaRegistryStore,
    OllamaRegistryV1,
)
from .ollama_runtime import OllamaReadinessStatus


MAX_REGISTRY_BYTES = 1024 * 1024
MAX_LIMIT_BYTES = 256 * 1024
MAX_RATE_LIMIT_BYTES = 256 * 1024
MAX_USAGE_BYTES = 1024 * 1024
MAX_EVENT_BYTES = 512 * 1024
MAX_SECRET_BYTES = 16 * 1024
_REMOTE_OLLAMA_DOCUMENT = PurePosixPath("remote-ollama-operations.json")
_REMOTE_OLLAMA_STATE_BYTES = 512 * 1024
_CREDENTIAL_BINDING_SALT_BYTES = 32
_CREDENTIAL_BINDING_DOMAIN = b"codex-master:gemini-credential-binding:v1\0"
GEMINI_MIN_REQUEST_INTERVAL_SECONDS = 60
GEMINI_TIER1_LOCAL_REQUEST_INTERVAL_SECONDS = 4
GEMINI_TIER1_SPEND_RATE_LIMIT_USD_PER_10_MINUTES = 10.0
GEMINI_TIER1_BILLING_CAP_USD_PER_MONTH = 250.0
GEMINI_QUOTA_SNAPSHOT_SOURCE = "user_supplied_ai_studio_snapshots_2026-08-11"
# The dashboard exports show different tiers for projects in the same local
# account group. Keep this project-scoped and do not infer Tier 1 from the
# account number alone.
GEMINI_PROJECT_BILLING_TIERS: dict[str, str] = {
    "the-hive-1": "tier1",
    "the-hive-2": "tier1",
    "the-hive-3": "tier0",
    "the-hive-4": "tier0",
    "the-hive-6": "tier0",
    "the-hive-10": "tier0",
}
GEMINI_QUOTA_SNAPSHOTS: dict[str, dict[str, dict[str, int]]] = {
    "tier0": {
        "gemini-3.1-flash-lite": {"rpm": 15, "tpm": 250_000, "rpd": 500},
        "gemini-3-flash": {"rpm": 5, "tpm": 250_000, "rpd": 20},
        "gemini-3.5-flash": {"rpm": 5, "tpm": 250_000, "rpd": 20},
    },
    "tier1": {
        "gemini-3.1-flash-lite": {"rpm": 4_000, "tpm": 4_000_000, "rpd": 150_000},
        "gemini-3-flash": {"rpm": 1_000, "tpm": 2_000_000, "rpd": 10_000},
        "gemini-3.5-flash": {"rpm": 1_000, "tpm": 2_000_000, "rpd": 10_000},
    },
}
# Only projects with a Rate Limit export get concrete RPM/TPM/RPD values.
# H3 and H10 have a visible free-tier label in Usage exports, but no concrete
# Rate Limit table in the supplied files, so their limits remain unknown.
GEMINI_PROJECT_QUOTA_SNAPSHOTS: dict[str, dict[str, dict[str, int]]] = {
    "the-hive-1": GEMINI_QUOTA_SNAPSHOTS["tier1"],
    "the-hive-2": GEMINI_QUOTA_SNAPSHOTS["tier1"],
    "the-hive-4": GEMINI_QUOTA_SNAPSHOTS["tier0"],
    "the-hive-6": GEMINI_QUOTA_SNAPSHOTS["tier0"],
}
GEMINI_REQUEST_LEASE_SECONDS = 120 * 60 + 60
GEMINI_INITIAL_429_COOLDOWN_SECONDS = 15 * 60
GEMINI_MAX_429_COOLDOWN_SECONDS = 24 * 60 * 60
_USAGE_QUOTA_SCOPES = frozenset({"model", "account", "unknown"})
_GEMINI_MAX_USAGE_QUOTA_RETRY_SECONDS = 3600
_ACCOUNT_ID_RE = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_LIMIT_REASON_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_T = TypeVar("_T")

GEMINI_GATE_DIAGNOSTICS: Mapping[str, Mapping[str, object]] = MappingProxyType({
    "gemini_ready": MappingProxyType({
        "severity": "info", "retryable": False, "action": "allow",
        "reason": "Gemini request admitted.",
    }),
    "gemini_local_rate_limited": MappingProxyType({
        "severity": "warning", "retryable": True, "action": "defer_until",
        "reason": "Gemini local request rate limit active.",
    }),
    "gemini_rpm_exhausted": MappingProxyType({
        "severity": "warning", "retryable": True, "action": "defer_until",
        "reason": "Known Gemini requests-per-minute limit reached.",
    }),
    "gemini_tpm_exhausted": MappingProxyType({
        "severity": "warning", "retryable": True, "action": "defer_until",
        "reason": "Known Gemini input-tokens-per-minute limit reached.",
    }),
    "gemini_rpd_exhausted": MappingProxyType({
        "severity": "warning", "retryable": True, "action": "defer_until",
        "reason": "Known Gemini requests-per-day limit reached.",
    }),
    "gemini_account_limited": MappingProxyType({
        "severity": "warning", "retryable": True, "action": "defer_until",
        "reason": "Gemini account has an active provider limit.",
    }),
    "gemini_model_limited": MappingProxyType({
        "severity": "warning", "retryable": True, "action": "defer_until",
        "reason": "Gemini model has an active provider limit.",
    }),
    "gemini_account_disabled": MappingProxyType({
        "severity": "error", "retryable": False, "action": "reject",
        "reason": "Gemini account is disabled.",
    }),
    "gemini_secret_missing": MappingProxyType({
        "severity": "error", "retryable": False, "action": "reject",
        "reason": "Gemini account credential is missing.",
    }),
    "gemini_auth_invalid": MappingProxyType({
        "severity": "error", "retryable": False, "action": "reject",
        "reason": "Gemini account authentication is invalid.",
    }),
    "gemini_auth_or_billing_denied": MappingProxyType({
        "severity": "error", "retryable": False, "action": "reject",
        "reason": "Gemini account authorization or billing access is denied.",
    }),
    "gemini_provider_unavailable": MappingProxyType({
        "severity": "warning", "retryable": True, "action": "reject",
        "reason": "Gemini provider is unavailable.",
    }),
    "gemini_model_unavailable": MappingProxyType({
        "severity": "error", "retryable": False, "action": "reject",
        "reason": "Gemini model is unavailable.",
    }),
    "gemini_runner_failed": MappingProxyType({
        "severity": "error", "retryable": False, "action": "reject",
        "reason": "Gemini probe contract was rejected or failed locally.",
    }),
    "gemini_account_limit_unknown": MappingProxyType({
        "severity": "warning", "retryable": True, "action": "reject",
        "reason": "Gemini account limit state is unknown.",
    }),
    "gemini_credential_unverified": MappingProxyType({
        "severity": "error", "retryable": False, "action": "reject",
        "reason": "Gemini account credential cannot be verified.",
    }),
    "gemini_probe_stale": MappingProxyType({
        "severity": "warning", "retryable": True, "action": "reject",
        "reason": "Gemini account probe is stale.",
    }),
    "gemini_account_unavailable": MappingProxyType({
        "severity": "error", "retryable": False, "action": "reject",
        "reason": "Gemini account is unavailable.",
    }),
    "gemini_limits_unknown": MappingProxyType({
        "severity": "warning", "retryable": False, "action": "allow",
        "reason": "Gemini dashboard limits are unknown; only observed counters are available.",
    }),
    "gemini_gate_unknown": MappingProxyType({
        "severity": "error", "retryable": False, "action": "reject",
        "reason": "Gemini gate state is unknown.",
    }),
})
_GEMINI_LEGACY_GATE_CODES = MappingProxyType({
    "ready": "gemini_ready",
    "limit_active": "gemini_account_limited",
    "probe_stale": "gemini_probe_stale",
    "gemini_local_rate_limit": "gemini_local_rate_limited",
    "account_disabled": "gemini_account_disabled",
    "account_provider_mismatch": "gemini_account_unavailable",
    "credential_binding_unknown": "gemini_credential_unverified",
    "secret_missing": "gemini_secret_missing",
    "auth_invalid": "gemini_auth_invalid",
    "auth_or_billing_denied": "gemini_auth_or_billing_denied",
    "provider_unavailable": "gemini_provider_unavailable",
    "model_unavailable": "gemini_model_unavailable",
    "runner_failed": "gemini_runner_failed",
    "limit_unknown": "gemini_account_limit_unknown",
})
_GEMINI_EVENT_REASON_CODES = frozenset({
    *GEMINI_GATE_DIAGNOSTICS,
    "account_limited",
    "auth_invalid",
    "auth_or_billing_denied",
    "model_unavailable",
    "provider_unavailable",
    "runner_failed",
    "secret_missing",
    "limit_active",
    "ready",
})


def map_gemini_gate_code(code: str) -> str:
    """Map historical gate reasons to one stable, public diagnostic code."""

    if not isinstance(code, str):
        return "gemini_gate_unknown"
    return _GEMINI_LEGACY_GATE_CODES.get(code, code if code in GEMINI_GATE_DIAGNOSTICS else "gemini_gate_unknown")


def _redacted_gemini_event_reason(reason: str | None) -> str | None:
    if reason is None:
        return None
    return reason if reason in _GEMINI_EVENT_REASON_CODES else "runner_failed"


class FleetConflictError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class FleetSecretError(ValueError):
    pass


class FleetRateLimitError(ValueError):
    def __init__(self, reason: str, retry_after_seconds: int) -> None:
        super().__init__(reason)
        self.reason = reason
        self.retry_after_seconds = max(0, int(retry_after_seconds))


@dataclass(frozen=True, slots=True)
class GeminiRequestReservation:
    account_id: str
    model: str | None
    reservation_id: str
    expires_at_utc: str


@dataclass(frozen=True, slots=True)
class AccountGateDecision:
    allowed: bool
    reason: str
    account_id: str | None
    generation: int


@dataclass(frozen=True, slots=True)
class GeminiGateDecision:
    action: str
    diagnostic_code: str
    reason: str
    severity: str
    retryable: bool
    account_id: str | None
    model: str | None
    defer_until: str | None = None
    target_agent_id: str | None = None
    openai_fallback_reason: str | None = None

    def public(self) -> dict[str, object]:
        return {
            "action": self.action,
            "diagnostic_code": self.diagnostic_code,
            "reason": self.reason,
            "severity": self.severity,
            "retryable": self.retryable,
            "account_id": self.account_id,
            "model": self.model,
            "defer_until": self.defer_until,
            "next_reset_at_utc": self.defer_until,
            "target_agent_id": self.target_agent_id,
            "openai_fallback_reason": self.openai_fallback_reason,
            "raw_output": "not_returned",
        }


@dataclass(frozen=True, slots=True)
class FleetPaths:
    root: Path = field(repr=False)
    registry: Path = field(repr=False)
    secrets: Path = field(repr=False)
    limits: Path = field(repr=False)
    rate_limits: Path = field(repr=False)
    lock: Path = field(repr=False)
    recovery: Path = field(repr=False)
    mutation_lock: Path = field(repr=False)
    usage: Path = field(repr=False)
    events: Path = field(repr=False)

    @classmethod
    def from_state_root(cls, root: Path) -> FleetPaths:
        fleet_root = root / "fleet"
        return cls(
            root=fleet_root,
            registry=fleet_root / "registry.json",
            secrets=fleet_root / "secrets",
            limits=fleet_root / "limits.json",
            rate_limits=fleet_root / "rate-limits.json",
            lock=fleet_root / "registry.lock",
            recovery=fleet_root / "recovery.json",
            mutation_lock=fleet_root / "mutation.lock",
            usage=fleet_root / "usage.json",
            events=fleet_root / "events.jsonl",
        )


@dataclass(frozen=True, slots=True)
class FleetPrivateIO:
    ensure_dir: Callable[[Path], None]
    read_text: Callable[[Path, int, str], str | None]
    replace_text: Callable[[Path, str], None]
    read_bytes: Callable[[Path, int, str], bytes | None]
    replace_bytes: Callable[[Path, bytes, int], None]
    lock: Callable[[], ContextManager[None]]
    utc_now: Callable[[], datetime]
    remove_file: Callable[[Path], bool] | None = None


@dataclass(frozen=True, slots=True)
class OllamaResourceSnapshotV1:
    host_ref: str
    generation: int
    observed_at_utc: str
    valid_until_utc: str
    green: bool
    headroom_seconds: int

    def __post_init__(self) -> None:
        try:
            observed = datetime.fromisoformat(
                self.observed_at_utc.replace("Z", "+00:00")
            )
            valid_until = datetime.fromisoformat(
                self.valid_until_utc.replace("Z", "+00:00")
            )
        except (AttributeError, ValueError):
            raise ValueError("ollama.resource_snapshot_invalid") from None
        if (
            not _ACCOUNT_ID_RE.fullmatch(self.host_ref)
            or type(self.generation) is not int
            or self.generation < 1
            or observed.tzinfo is None
            or valid_until.tzinfo is None
            or valid_until <= observed
            or type(self.green) is not bool
            or type(self.headroom_seconds) is not int
            or self.headroom_seconds < 0
        ):
            raise ValueError("ollama.resource_snapshot_invalid")


@dataclass(frozen=True, slots=True)
class OllamaFleetPlanV1:
    plan_id: str
    plan_digest: str
    registry_generation: int
    resource_generation: int | None
    instance: OllamaInstanceV1 = field(repr=False)
    host_plan: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class OllamaHiveLaneV1:
    lane_ref: str
    instance_ref: str
    host_ref: str
    model_ref: str
    provider_model_id: str
    task_profile: str = "simple_only"


@dataclass(frozen=True, slots=True)
class OllamaApplyResultV1:
    registry: OllamaRegistryV1
    instance: OllamaInstanceV1
    readiness: OllamaReadinessStatus
    hive_lanes: tuple[OllamaHiveLaneV1, ...]


@dataclass(frozen=True, slots=True)
class _RemoteOllamaPlanV1:
    operation_id: str
    plan_digest: str
    agent_plan_digest: str
    registry_generation: int
    resource_generation: int | None
    instance: OllamaInstanceV1


def _remote_instance_document(instance: OllamaInstanceV1) -> dict[str, object]:
    return {
        "ref": instance.ref,
        "label": instance.label,
        "host_ref": instance.host_ref,
        "ollama_executable": instance.ollama_executable,
        "models_directory": instance.models_directory,
        "selected_model_refs": list(instance.selected_model_refs),
        "allowed_cpus": instance.allowed_cpus,
        "cpu_quota_percent": instance.cpu_quota_percent,
        "cpu_weight": instance.cpu_weight,
        "lifecycle_state": instance.lifecycle_state,
        "readiness_state": instance.readiness_state,
    }


def _remote_instance_from_document(value: object) -> OllamaInstanceV1:
    required = {
        "ref",
        "label",
        "host_ref",
        "ollama_executable",
        "models_directory",
        "selected_model_refs",
        "allowed_cpus",
        "cpu_quota_percent",
        "cpu_weight",
        "lifecycle_state",
        "readiness_state",
    }
    if not isinstance(value, Mapping) or set(value) != required:
        raise FleetConflictError("resource.host_response_invalid")
    selected = value["selected_model_refs"]
    if not isinstance(selected, (list, tuple)) or any(
        not isinstance(ref, str) for ref in selected
    ):
        raise FleetConflictError("resource.host_response_invalid")
    try:
        return OllamaInstanceV1(
            cast(str, value["ref"]),
            cast(str, value["label"]),
            cast(str, value["host_ref"]),
            cast(str, value["ollama_executable"]),
            cast(str, value["models_directory"]),
            tuple(selected),
            cast(str, value["allowed_cpus"]),
            cast(int, value["cpu_quota_percent"]),
            cast(int, value["cpu_weight"]),
            cast(str, value["lifecycle_state"]),
            cast(str, value["readiness_state"]),
        )
    except (TypeError, ValueError):
        raise FleetConflictError("resource.host_response_invalid") from None


def _readiness_document(value: OllamaReadinessStatus) -> dict[str, object]:
    return {
        "ready": value.ready,
        "reason_codes": list(value.reason_codes),
        "process_running": value.process_running,
        "cgroup_member": value.cgroup_member,
        "loopback_endpoint_reachable": value.loopback_endpoint_reachable,
        "available_model_ids": list(value.available_model_ids),
    }


def _readiness_from_document(value: object) -> OllamaReadinessStatus:
    if not isinstance(value, Mapping) or set(value) != {
        "ready",
        "reason_codes",
        "process_running",
        "cgroup_member",
        "loopback_endpoint_reachable",
        "available_model_ids",
    }:
        raise FleetConflictError("resource.host_response_invalid")
    try:
        return OllamaReadinessStatus(
            value["ready"],
            tuple(value["reason_codes"]),
            value["process_running"],
            value["cgroup_member"],
            value["loopback_endpoint_reachable"],
            tuple(value["available_model_ids"]),
        )
    except (TypeError, ValueError):
        raise FleetConflictError("resource.host_response_invalid") from None


class FleetService:
    def __init__(
        self,
        paths: FleetPaths,
        private_io: FleetPrivateIO,
        *,
        pool_root: Path,
        probe_max_age_seconds: int = 900,
        read_only: bool = False,
        ollama_registry: OllamaRegistryStore | None = None,
        ollama_transport: object | None = None,
        agent_operations: AgentOperationStore | None = None,
        ollama_resource_snapshot: Callable[
            [str], OllamaResourceSnapshotV1 | None
        ] | None = None,
    ) -> None:
        self._paths = paths
        self._io = private_io
        self._pool_root = pool_root
        if not isinstance(read_only, bool):
            raise ValueError("invalid_fleet_read_only")
        self._read_only = read_only
        if (
            isinstance(probe_max_age_seconds, bool)
            or not isinstance(probe_max_age_seconds, int)
            or not 1 <= probe_max_age_seconds <= 900
        ):
            raise ValueError("invalid_probe_max_age")
        self._probe_max_age_seconds = probe_max_age_seconds
        self._ollama_registry = ollama_registry
        self._ollama_transport = ollama_transport
        self._agent_operations = agent_operations
        self._ollama_remote_state = None
        if ollama_registry is not None and agent_operations is not None:
            try:
                for directory in (paths.root.parent, paths.root):
                    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
                    os.chmod(directory, 0o700)
                self._ollama_remote_state = HiveStateStore(paths.root / "ollama-remote")
            except (HiveStateError, OSError):
                raise ValueError("ollama.remote_state_unavailable") from None
        self._ollama_resource_snapshot = ollama_resource_snapshot
        self._ollama_lock = threading.RLock()
        self._ollama_plans: dict[str, OllamaFleetPlanV1] = {}
        self._ollama_applied: dict[str, OllamaApplyResultV1] = {}
        self._ollama_ready: dict[str, OllamaReadinessStatus] = {}
        self._ollama_executions: dict[str, tuple[object, int]] = {}
        self._ollama_remote_plans: dict[str, _RemoteOllamaPlanV1] = {}
        self._ollama_remote_operations: dict[str, tuple[str, _RemoteOllamaPlanV1]] = {}
        self._ollama_remote_applied: dict[str, _RemoteOllamaPlanV1] = {}

    def _require_ollama(self) -> tuple[OllamaRegistryStore, object]:
        if self._ollama_registry is None or self._ollama_transport is None:
            raise FleetConflictError("ollama.not_configured")
        return self._ollama_registry, self._ollama_transport

    def _remote_document(self) -> dict[str, object]:
        """Load the private, restart-safe remote operation index."""

        state = self._ollama_remote_state
        if state is None:
            raise FleetConflictError("ollama.transport_invalid")
        try:
            with state.locked():
                return self._remote_document_locked(state)
        except HiveStateError:
            raise FleetConflictError("resource.host_response_invalid") from None

    @staticmethod
    def _remote_document_locked(state: HiveStateStore) -> dict[str, object]:
        try:
            document = dict(
                state.read_json_locked(
                    _REMOTE_OLLAMA_DOCUMENT, max_bytes=_REMOTE_OLLAMA_STATE_BYTES
                )
            )
        except HiveStateError as error:
            if str(error) == "state_not_found":
                return {"schema_version": 1, "operations": {}, "ready": {}}
            raise
        if (
            set(document) != {"schema_version", "operations", "ready"}
            or document["schema_version"] != 1
            or not isinstance(document["operations"], dict)
            or not isinstance(document["ready"], dict)
        ):
            raise FleetConflictError("resource.host_response_invalid")
        return document

    def _mutate_remote_document(
        self, mutate: Callable[[dict[str, object]], None]
    ) -> None:
        state = self._ollama_remote_state
        if state is None:
            raise FleetConflictError("ollama.transport_invalid")
        try:
            with state.locked():
                document = self._remote_document_locked(state)
                mutate(document)
                self._remote_document_locked_validate(document)
                state.replace_json_locked(_REMOTE_OLLAMA_DOCUMENT, document)
        except HiveStateError:
            raise FleetConflictError("resource.host_response_invalid") from None

    @staticmethod
    def _remote_document_locked_validate(document: object) -> None:
        if (
            not isinstance(document, Mapping)
            or set(document) != {"schema_version", "operations", "ready"}
            or document["schema_version"] != 1
            or not isinstance(document["operations"], dict)
            or not isinstance(document["ready"], dict)
        ):
            raise FleetConflictError("resource.host_response_invalid")

    def _remote_plan_from_record(
        self, operation_id: str, record: object
    ) -> _RemoteOllamaPlanV1:
        required = {
            "action",
            "plan_id",
            "plan_digest",
            "agent_plan_digest",
            "registry_generation",
            "resource_generation",
            "instance",
            "arguments_digest",
        }
        if (
            not isinstance(record, Mapping)
            or not required.issubset(record)
            or set(record) - required - {"completed", "instance_ref", "completion"}
        ):
            raise FleetConflictError("resource.host_response_invalid")
        completion = record.get("completion")
        if completion is not None and (
            not isinstance(completion, Mapping)
            or set(completion) != {"state", "receipt_digest", "phase"}
            or completion.get("state") not in {"succeeded", "failed", "unknown"}
            or not isinstance(completion.get("receipt_digest"), str)
            or completion.get("phase")
            not in {"prepared", "owner_applied", "queue_completed"}
        ):
            raise FleetConflictError("resource.host_response_invalid")
        if (
            not isinstance(operation_id, str)
            or not isinstance(record["plan_id"], str)
            or not isinstance(record["plan_digest"], str)
            or not isinstance(record["agent_plan_digest"], str)
            or not isinstance(record["registry_generation"], int)
            or (
                record["resource_generation"] is not None
                and not isinstance(record["resource_generation"], int)
            )
            or not isinstance(record["arguments_digest"], str)
        ):
            raise FleetConflictError("resource.host_response_invalid")
        instance = _remote_instance_from_document(record["instance"])
        return _RemoteOllamaPlanV1(
            operation_id,
            record["plan_digest"],
            record["agent_plan_digest"],
            record["registry_generation"],
            record["resource_generation"],
            instance,
        )

    @staticmethod
    def _completion_saga_digest(receipt: AgentReceiptV1) -> str:
        return "sha256:" + hashlib.sha256(
            json.dumps(
                {
                    "operation_id": receipt.operation_id,
                    "lease_id": receipt.lease_id,
                    "lease_epoch": receipt.lease_epoch,
                    "attempt": receipt.attempt,
                    "plan_digest": receipt.plan_digest,
                    "arguments_digest": receipt.arguments_digest,
                    "envelope_digest": receipt.envelope_digest,
                    "state": receipt.state,
                    "reason_codes": receipt.reason_codes,
                    "result_digest": receipt.result_digest,
                    "result": serialize_agent_result(receipt.result),
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()

    def _prepare_remote_completion(self, receipt: AgentReceiptV1) -> None:
        digest = self._completion_saga_digest(receipt)

        def prepare(document: dict[str, object]) -> None:
            record = cast(dict[str, object], document["operations"]).get(
                receipt.operation_id
            )
            if not isinstance(record, dict):
                raise FleetConflictError("resource.host_response_invalid")
            completion = record.get("completion")
            expected = {"state": receipt.state, "receipt_digest": digest}
            if completion is None:
                record["completion"] = {**expected, "phase": "prepared"}
                return
            if (
                not isinstance(completion, Mapping)
                or completion.get("state") != receipt.state
                or completion.get("receipt_digest") != digest
                or completion.get("phase")
                not in {"prepared", "owner_applied", "queue_completed"}
            ):
                raise FleetConflictError("resource.host_response_invalid")

        self._mutate_remote_document(prepare)

    def _mark_remote_owner_applied(
        self,
        receipt: AgentReceiptV1,
        *,
        instance_ref: str | None,
        readiness: OllamaReadinessStatus | None,
    ) -> None:
        digest = self._completion_saga_digest(receipt)

        def owner_applied(document: dict[str, object]) -> None:
            record = cast(dict[str, object], document["operations"]).get(
                receipt.operation_id
            )
            if not isinstance(record, dict):
                raise FleetConflictError("resource.host_response_invalid")
            completion = record.get("completion")
            if (
                not isinstance(completion, dict)
                or completion.get("state") != receipt.state
                or completion.get("receipt_digest") != digest
                or completion.get("phase") not in {"prepared", "owner_applied", "queue_completed"}
            ):
                raise FleetConflictError("resource.host_response_invalid")
            if completion["phase"] == "queue_completed":
                return
            completion["phase"] = "owner_applied"
            if instance_ref is not None:
                record["instance_ref"] = instance_ref
                ready = cast(dict[str, object], document["ready"])
                if readiness is None:
                    ready.pop(instance_ref, None)
                else:
                    ready[instance_ref] = _readiness_document(readiness)

        self._mutate_remote_document(owner_applied)

    def _remote_plan(self, plan_id: str) -> _RemoteOllamaPlanV1 | None:
        if self._ollama_remote_state is None:
            return None
        document = self._remote_document()
        record = cast(dict[str, object], document["operations"]).get(plan_id)
        if record is None:
            return None
        plan = self._remote_plan_from_record(plan_id, record)
        if record.get("action") != "plan" or record.get("plan_id") != plan_id:
            return None
        return plan

    def _remote_operation(
        self, operation_id: str
    ) -> tuple[str, _RemoteOllamaPlanV1, Mapping[str, object]] | None:
        if self._ollama_remote_state is None:
            return None
        document = self._remote_document()
        record = cast(dict[str, object], document["operations"]).get(operation_id)
        if record is None:
            self._recover_remote_owner_from_queue(operation_id)
            document = self._remote_document()
            record = cast(dict[str, object], document["operations"]).get(operation_id)
            if record is None:
                return None
        if not isinstance(record, Mapping):
            raise FleetConflictError("resource.host_response_invalid")
        action = record.get("action")
        plan_id = record.get("plan_id")
        if action not in {"plan", "apply", "probe", "stop"} or not isinstance(
            plan_id, str
        ):
            raise FleetConflictError("resource.host_response_invalid")
        plan = self._remote_plan(plan_id)
        if plan is None:
            raise FleetConflictError("resource.host_response_invalid")
        return action, plan, record

    def _recover_remote_owner_from_queue(self, operation_id: str) -> None:
        """Rebuild any remote owner from its queue-committed bounded envelope.

        The recovery lookup is one exact operation-id lookup, never an index
        scan.  Action owners can only be reconstructed through the durable
        plan owner named by their exact ``plan_id`` fence.
        """
        if self._agent_operations is None or self._ollama_registry is None:
            return
        try:
            context = self._agent_operations.owner_context(operation_id)
            queued = self._agent_operations.get(operation_id)
        except AgentOperationError:
            return
        if (
            context is None
            or context.get("owner") != "ollama.remote"
            or context.get("schema_version") != 1
            or context.get("action") != queued.action
            or context.get("queue_plan_digest") != queued.plan_digest
            or context.get("registry_generation") != queued.registry_generation
        ):
            return
        instance_ref = context.get("instance_ref")
        host_ref = context.get("host_ref")
        resource_generation = context.get("resource_generation")
        if (
            not isinstance(instance_ref, str)
            or not isinstance(host_ref, str)
            or (resource_generation is not None and not isinstance(resource_generation, int))
        ):
            return
        try:
            queued_instance = _remote_instance_from_document(context.get("instance"))
        except FleetConflictError:
            return
        if queued_instance.ref != instance_ref or queued_instance.host_ref != host_ref:
            return
        action = cast(str, context["action"])
        if action != "plan":
            plan_id = context.get("plan_id")
            if not isinstance(plan_id, str):
                return
            plan = self._remote_plan(plan_id)
            if (
                plan is None
                or plan.instance.ref != instance_ref
                or plan.instance.host_ref != host_ref
                or _remote_instance_document(plan.instance)
                != _remote_instance_document(queued_instance)
                or plan.resource_generation != resource_generation
                or context.get("plan_precondition_digest")
                != "sha256:" + plan.agent_plan_digest
            ):
                return
            payload = {
                "action": action,
                "plan_id": plan.operation_id,
                "plan_digest": plan.plan_digest,
                "agent_plan_digest": queued.plan_digest.removeprefix("sha256:"),
                "registry_generation": context.get("ollama_registry_generation"),
                "resource_generation": plan.resource_generation,
                "instance": _remote_instance_document(plan.instance),
                "arguments_digest": queued.arguments_digest,
            }
            self._record_recovered_remote_owner(operation_id, payload)
            return
        registry = self._ollama_registry.load()
        if registry.generation != context.get("ollama_registry_generation"):
            return
        instance = queued_instance
        agent_digest = queued.plan_digest.removeprefix("sha256:")
        plan_digest = hashlib.sha256(
            json.dumps(
                {
                    "instance": {
                        "ref": instance.ref,
                        "host_ref": instance.host_ref,
                        "models": instance.selected_model_refs,
                        "allowed_cpus": instance.allowed_cpus,
                        "cpu_quota_percent": instance.cpu_quota_percent,
                        "cpu_weight": instance.cpu_weight,
                    },
                    "registry_generation": registry.generation,
                    "resource_generation": resource_generation,
                    "host_plan_digest": "sha256:" + agent_digest,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        payload = {
            "action": "plan", "plan_id": operation_id, "plan_digest": plan_digest,
            "agent_plan_digest": agent_digest, "registry_generation": registry.generation,
            "resource_generation": resource_generation,
            "instance": _remote_instance_document(instance),
            "arguments_digest": queued.arguments_digest,
        }
        self._record_recovered_remote_owner(operation_id, payload)

    def _record_recovered_remote_owner(
        self, operation_id: str, payload: dict[str, object]
    ) -> None:
        def record_owner(document: dict[str, object]) -> None:
            operations = cast(dict[str, object], document["operations"])
            prior = operations.get(operation_id)
            if prior is None:
                operations[operation_id] = payload
            elif not isinstance(prior, Mapping) or any(prior.get(k) != v for k, v in payload.items()):
                raise FleetConflictError("resource.host_response_invalid")
        self._mutate_remote_document(record_owner)

    def _remote_applied(self, instance_ref: str) -> _RemoteOllamaPlanV1 | None:
        if self._ollama_remote_state is None:
            return None
        document = self._remote_document()
        for operation_id, record in cast(dict[str, object], document["operations"]).items():
            if not isinstance(operation_id, str) or not isinstance(record, Mapping):
                raise FleetConflictError("resource.host_response_invalid")
            if (
                record.get("action") == "apply"
                and record.get("instance_ref") == instance_ref
                and record.get("completed") is True
            ):
                plan_id = record.get("plan_id")
                if not isinstance(plan_id, str):
                    raise FleetConflictError("resource.host_response_invalid")
                return self._remote_plan(plan_id)
        return None

    def _remote_stopped(self, instance_ref: str) -> bool:
        if self._ollama_remote_state is None:
            return False
        document = self._remote_document()
        return any(
            isinstance(record, Mapping)
            and record.get("action") == "stop"
            and record.get("instance_ref") == instance_ref
            and record.get("completed") is True
            for record in cast(dict[str, object], document["operations"]).values()
        )

    def _record_remote_operation(
        self,
        operation: OperationV1,
        *,
        action: str,
        plan: _RemoteOllamaPlanV1,
        agent_plan_digest: str,
    ) -> None:
        if self._agent_operations is None:
            raise FleetConflictError("ollama.transport_invalid")
        try:
            queued = self._agent_operations.get(operation.id)
            owner_context = self._agent_operations.owner_context(operation.id)
        except AgentOperationError:
            raise FleetConflictError("ollama.transport_invalid") from None
        if (
            queued.kind != "ollama.instance"
            or queued.action != action
            or queued.plan_digest != "sha256:" + agent_plan_digest
            or owner_context is None
            or owner_context.get("action") != action
            or owner_context.get("host_ref") != plan.instance.host_ref
            or owner_context.get("instance_ref") != plan.instance.ref
            or owner_context.get("registry_generation") != queued.registry_generation
            or owner_context.get("resource_generation") != plan.resource_generation
            or owner_context.get("queue_plan_digest") != queued.plan_digest
            or owner_context.get("plan_precondition_digest")
            != "sha256:"
            + (plan.agent_plan_digest if action != "plan" else agent_plan_digest)
            or (
                action != "plan"
                and owner_context.get("plan_id") != plan.operation_id
            )
        ):
            raise FleetConflictError("ollama.transport_invalid")
        payload = {
            "action": action,
            "plan_id": plan.operation_id,
            "plan_digest": plan.plan_digest,
            "agent_plan_digest": agent_plan_digest,
            "registry_generation": (
                plan.registry_generation
                if action == "plan"
                else owner_context.get("ollama_registry_generation")
            ),
            "resource_generation": plan.resource_generation,
            "instance": _remote_instance_document(plan.instance),
            "arguments_digest": queued.arguments_digest,
        }
        def record(document: dict[str, object]) -> None:
            operations = cast(dict[str, object], document["operations"])
            prior = operations.get(operation.id)
            if prior is not None:
                if (
                    not isinstance(prior, Mapping)
                    or any(prior.get(key) != value for key, value in payload.items())
                    or set(prior) - set(payload) - {
                        "completed",
                        "instance_ref",
                        "completion",
                    }
                ):
                    raise FleetConflictError("resource.host_response_invalid")
                return
            operations[operation.id] = payload

        self._mutate_remote_document(record)

    def _mark_remote_completed(
        self,
        receipt: AgentReceiptV1,
        *,
        instance_ref: str | None = None,
        readiness: OllamaReadinessStatus | None = None,
    ) -> None:
        digest = self._completion_saga_digest(receipt)

        def complete(document: dict[str, object]) -> None:
            operations = cast(dict[str, object], document["operations"])
            record = operations.get(receipt.operation_id)
            if not isinstance(record, dict):
                raise FleetConflictError("resource.host_response_invalid")
            completion = record.get("completion")
            if (
                not isinstance(completion, dict)
                or completion.get("state") != receipt.state
                or completion.get("receipt_digest") != digest
                or completion.get("phase")
                not in {"prepared", "owner_applied", "queue_completed"}
            ):
                raise FleetConflictError("resource.host_response_invalid")
            updated = dict(record)
            updated["completed"] = True
            updated_completion = dict(completion)
            updated_completion["phase"] = "queue_completed"
            updated["completion"] = updated_completion
            if instance_ref is not None:
                updated["instance_ref"] = instance_ref
            operations[receipt.operation_id] = updated
            ready = cast(dict[str, object], document["ready"])
            if instance_ref is not None:
                if readiness is None:
                    ready.pop(instance_ref, None)
                else:
                    ready[instance_ref] = _readiness_document(readiness)

        self._mutate_remote_document(complete)

    def ollama_models(self) -> tuple[OllamaModelV1, ...]:
        registry, _transport = self._require_ollama()
        return registry.load().models

    def ollama_instances(self) -> tuple[OllamaInstanceV1, ...]:
        registry, _transport = self._require_ollama()
        return registry.load().instances

    def ollama_generation(self) -> int:
        registry, _transport = self._require_ollama()
        return registry.load().generation

    def ollama_plan_digest(self, plan_id: str) -> str | None:
        """Return a persisted remote digest after a service restart."""

        if not isinstance(plan_id, str):
            return None
        remote = self._remote_plan(plan_id)
        if remote is not None:
            return "sha256:" + remote.plan_digest
        local = self._ollama_plans.get(plan_id)
        return None if local is None else "sha256:" + local.plan_digest

    def _assert_remote_resource_fence(self, plan: _RemoteOllamaPlanV1) -> None:
        """Require the exact attestation that admitted this remote plan.

        The value is carried in the agent envelope as well; this check stops a
        later master-side enqueue before an outdated headroom observation can
        reach the host.
        """

        if plan.resource_generation is None:
            return
        snapshot = (
            self._ollama_resource_snapshot(plan.instance.host_ref)
            if self._ollama_resource_snapshot is not None
            else None
        )
        if not isinstance(snapshot, OllamaResourceSnapshotV1):
            raise FleetConflictError("ollama.resource_headroom_required")
        now = self._io.utc_now()
        observed = datetime.fromisoformat(snapshot.observed_at_utc.replace("Z", "+00:00"))
        valid_until = datetime.fromisoformat(
            snapshot.valid_until_utc.replace("Z", "+00:00")
        )
        if (
            snapshot.host_ref != plan.instance.host_ref
            or snapshot.generation != plan.resource_generation
            or not snapshot.green
            or snapshot.headroom_seconds < 3600
            or not observed <= now < valid_until
            or (valid_until - now).total_seconds() < 3600
        ):
            raise FleetConflictError("ollama.resource_headroom_required")

    def probe_ollama_instance(
        self,
        instance_ref: str,
        *,
        expected_generation: int,
    ) -> OllamaReadinessStatus | OperationV1:
        registry, transport = self._require_ollama()
        with self._ollama_lock:
            current = registry.load()
            if (
                not isinstance(instance_ref, str)
                or type(expected_generation) is not int
                or current.generation != expected_generation
            ):
                raise FleetConflictError("generation_conflict")
            instance = next(
                (
                    candidate
                    for candidate in current.instances
                    if candidate.ref == instance_ref
                ),
                None,
            )
            remote_plan = self._remote_applied(instance_ref)
            if remote_plan is not None:
                if instance is None:
                    raise FleetConflictError("ollama.runtime_not_owned")
                self._assert_remote_resource_fence(remote_plan)
                try:
                    queued = transport.probe_remote(
                        remote_plan.instance,
                        generation=expected_generation,
                        resource_generation=remote_plan.resource_generation,
                        plan_digest=remote_plan.plan_digest,
                        plan_precondition_digest=remote_plan.agent_plan_digest,
                        owner_plan_id=remote_plan.operation_id,
                    )
                except AttributeError:
                    raise FleetConflictError("ollama.transport_invalid") from None
                if type(queued) is not OperationV1:
                    raise FleetConflictError("ollama.transport_invalid")
                self._ollama_remote_operations[queued.id] = ("probe", remote_plan)
                self._record_remote_operation(
                    queued,
                    action="probe",
                    plan=remote_plan,
                    agent_plan_digest=remote_plan.plan_digest,
                )
                return queued
            execution_record = self._ollama_executions.get(instance_ref)
            if instance is None or execution_record is None:
                raise FleetConflictError("ollama.runtime_not_owned")
            execution, fence = execution_record
            readiness = transport.probe(execution, current_fence=fence)
            if not isinstance(readiness, OllamaReadinessStatus):
                raise FleetConflictError("ollama.transport_invalid")
            readiness_state = "ready" if readiness.ready else "not_ready"
            lifecycle_state = "running" if readiness.process_running else "failed"
            if readiness.ready:
                self._ollama_ready[instance_ref] = readiness
            else:
                self._ollama_ready.pop(instance_ref, None)
            if (
                instance.readiness_state != readiness_state
                or instance.lifecycle_state != lifecycle_state
            ):
                updated = dataclass_replace(
                    instance,
                    readiness_state=readiness_state,
                    lifecycle_state=lifecycle_state,
                )
                registry.replace(
                    models=current.models,
                    instances=tuple(
                        updated if candidate.ref == instance_ref else candidate
                        for candidate in current.instances
                    ),
                    expected_generation=current.generation,
                )
            return readiness

    def plan_ollama_instance(
        self,
        instance: OllamaInstanceV1,
        *,
        expected_generation: int,
    ) -> OllamaFleetPlanV1 | OperationV1:
        registry, transport = self._require_ollama()
        current = registry.load()
        if (
            type(instance) is not OllamaInstanceV1
            or type(expected_generation) is not int
            or current.generation != expected_generation
        ):
            raise FleetConflictError("generation_conflict")
        existing = next(
            (candidate for candidate in current.instances if candidate.ref == instance.ref),
            None,
        )
        running_on_host = sum(
            candidate.host_ref == instance.host_ref
            and candidate.lifecycle_state == "running"
            and candidate.ref != instance.ref
            for candidate in current.instances
        )
        if running_on_host >= 4 and (
            existing is None or existing.lifecycle_state != "running"
        ):
            code = (
                "ollama.local_limit_reached"
                if instance.host_ref == CONTROL_HOST_REF
                else "ollama.host_limit_reached"
            )
            raise FleetConflictError(code)
        resource_generation = None
        if running_on_host >= 2 and (
            existing is None or existing.lifecycle_state != "running"
        ):
            snapshot = (
                self._ollama_resource_snapshot(instance.host_ref)
                if self._ollama_resource_snapshot is not None
                else None
            )
            now = self._io.utc_now()
            if not isinstance(snapshot, OllamaResourceSnapshotV1):
                raise FleetConflictError("ollama.resource_headroom_required")
            observed = datetime.fromisoformat(
                snapshot.observed_at_utc.replace("Z", "+00:00")
            )
            valid_until = datetime.fromisoformat(
                snapshot.valid_until_utc.replace("Z", "+00:00")
            )
            if (
                snapshot.host_ref != instance.host_ref
                or not snapshot.green
                or snapshot.headroom_seconds < 3600
                or not observed <= now < valid_until
                or (valid_until - now).total_seconds() < 3600
            ):
                raise FleetConflictError("ollama.resource_headroom_required")
            resource_generation = snapshot.generation
        try:
            host_plan = transport.plan(
                instance,
                generation=current.generation,
                resource_generation=resource_generation,
            )
        except AttributeError:
            raise FleetConflictError("ollama.transport_invalid") from None
        plan_id = secrets.token_hex(16)
        host_digest = getattr(host_plan, "plan_digest", None)
        if not isinstance(host_digest, str):
            raise FleetConflictError("ollama.transport_invalid")
        plan_digest = hashlib.sha256(
            json.dumps(
                {
                    "instance": {
                        "ref": instance.ref,
                        "host_ref": instance.host_ref,
                        "models": instance.selected_model_refs,
                        "allowed_cpus": instance.allowed_cpus,
                        "cpu_quota_percent": instance.cpu_quota_percent,
                        "cpu_weight": instance.cpu_weight,
                    },
                    "registry_generation": current.generation,
                    "resource_generation": resource_generation,
                    "host_plan_digest": host_digest,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        with self._ollama_lock:
            if type(host_plan) is OperationV1:
                remote_plan = _RemoteOllamaPlanV1(
                    host_plan.id,
                    plan_digest,
                    host_digest.removeprefix("sha256:"),
                    current.generation,
                    resource_generation,
                    instance,
                )
                self._ollama_remote_plans[host_plan.id] = remote_plan
                operation = dataclass_replace(
                    host_plan, plan_digest="sha256:" + plan_digest
                )
                self._record_remote_operation(
                    operation,
                    action="plan",
                    plan=remote_plan,
                    agent_plan_digest=remote_plan.agent_plan_digest,
                )
                return operation
            planned = OllamaFleetPlanV1(
                plan_id,
                plan_digest,
                current.generation,
                resource_generation,
                instance,
                host_plan,
            )
            self._ollama_plans[plan_id] = planned
        return planned

    def apply_ollama_instance(
        self,
        plan_id: str,
        *,
        expected_generation: int,
    ) -> OllamaApplyResultV1 | OperationV1:
        registry, transport = self._require_ollama()
        with self._ollama_lock:
            remote_plan = self._remote_plan(plan_id)
            if remote_plan is not None:
                if (
                    type(expected_generation) is not int
                    or remote_plan.registry_generation != expected_generation
                    or registry.load().generation != expected_generation
                ):
                    raise FleetConflictError("control.plan_stale")
                self._assert_remote_resource_fence(remote_plan)
                if self._agent_operations is None:
                    raise FleetConflictError("ollama.transport_invalid")
                try:
                    view = self._agent_operations.get(remote_plan.operation_id)
                    result = self._agent_operations.result(remote_plan.operation_id)
                except AgentOperationError as error:
                    raise FleetConflictError(error.code) from None
                if view.state == "unknown":
                    raise FleetConflictError("host.operation_unknown")
                if view.state != "succeeded" or result is None:
                    raise FleetConflictError("control.plan_stale")
                if (
                    result.kind != "ollama.instance"
                    or result.action != "plan"
                    or set(result.payload) != {"plan_ref"}
                    or type(result.payload["plan_ref"]) is not str
                ):
                    raise FleetConflictError("ollama.transport_invalid")
                try:
                    queued = transport.apply_remote(
                        remote_plan.instance,
                        generation=remote_plan.registry_generation,
                        resource_generation=remote_plan.resource_generation,
                        plan_digest=remote_plan.plan_digest,
                        plan_ref=result.payload["plan_ref"],
                        plan_precondition_digest=remote_plan.agent_plan_digest,
                        owner_plan_id=remote_plan.operation_id,
                    )
                except AttributeError:
                    raise FleetConflictError("ollama.transport_invalid") from None
                if type(queued) is not OperationV1:
                    raise FleetConflictError("ollama.transport_invalid")
                self._ollama_remote_operations[queued.id] = ("apply", remote_plan)
                self._record_remote_operation(
                    queued,
                    action="apply",
                    plan=remote_plan,
                    agent_plan_digest=remote_plan.plan_digest,
                )
                return queued
            applied = self._ollama_applied.get(plan_id)
            if applied is not None:
                return applied
            plan = self._ollama_plans.get(plan_id)
            if (
                plan is None
                or type(expected_generation) is not int
                or plan.registry_generation != expected_generation
            ):
                raise FleetConflictError("control.plan_stale")
            current = registry.load()
            if current.generation != expected_generation:
                raise FleetConflictError("control.plan_stale")
            execution = None
            try:
                fence = getattr(plan.host_plan, "fence")
                execution = transport.apply(plan.host_plan, current_fence=fence)
                readiness = transport.probe(execution, current_fence=fence)
                models_by_ref = {model.ref: model for model in current.models}
                selected_models = tuple(
                    models_by_ref[ref] for ref in plan.instance.selected_model_refs
                )
                if (
                    not isinstance(readiness, OllamaReadinessStatus)
                    or not readiness.ready
                    or not {
                        model.provider_model_id for model in selected_models
                    }.issubset(readiness.available_model_ids)
                ):
                    raise FleetConflictError("ollama.instance_not_ready")
                ready_instance = dataclass_replace(
                    plan.instance,
                    lifecycle_state="running",
                    readiness_state="ready",
                )
                instances = tuple(
                    ready_instance if candidate.ref == ready_instance.ref else candidate
                    for candidate in current.instances
                )
                if all(candidate.ref != ready_instance.ref for candidate in current.instances):
                    instances += (ready_instance,)
                stored = registry.replace(
                    models=current.models,
                    instances=instances,
                    expected_generation=current.generation,
                )
            except Exception:
                cleanup_failed = False
                if execution is not None:
                    try:
                        transport.stop(execution, current_fence=fence)
                    except Exception:
                        cleanup_failed = True
                self._ollama_plans.pop(plan_id, None)
                if cleanup_failed:
                    raise FleetConflictError("ollama.cleanup_failed") from None
                raise
            self._ollama_ready[ready_instance.ref] = readiness
            self._ollama_executions[ready_instance.ref] = (execution, fence)
            result = OllamaApplyResultV1(
                stored,
                ready_instance,
                readiness,
                self.ollama_hive_lanes(),
            )
            self._ollama_applied[plan_id] = result
            return result

    def ollama_hive_lanes(self) -> tuple[OllamaHiveLaneV1, ...]:
        registry, _transport = self._require_ollama()
        current = registry.load()
        models = {model.ref: model for model in current.models}
        persisted_ready: Mapping[str, object] = {}
        if self._ollama_remote_state is not None:
            persisted_ready = cast(Mapping[str, object], self._remote_document()["ready"])
        lanes = []
        for instance in current.instances:
            readiness = self._ollama_ready.get(instance.ref)
            if readiness is None and instance.ref in persisted_ready:
                readiness = _readiness_from_document(persisted_ready[instance.ref])
            if (
                instance.lifecycle_state != "running"
                or instance.readiness_state != "ready"
                or readiness is None
                or not readiness.ready
            ):
                continue
            for model_ref in instance.selected_model_refs:
                model = models.get(model_ref)
                if (
                    model is None
                    or not model.installed
                    or not model.hive_enabled
                    or not model.simple_only
                    or model.provider_model_id not in readiness.available_model_ids
                ):
                    continue
                lanes.append(
                    OllamaHiveLaneV1(
                        f"ollama:{instance.ref}:{model.ref}",
                        instance.ref,
                        instance.host_ref,
                        model.ref,
                        model.provider_model_id,
                    )
                )
        return tuple(lanes)

    def stop_ollama_instance(
        self, instance_ref: str, *, expected_generation: int
    ) -> OperationV1 | None:
        registry, transport = self._require_ollama()
        with self._ollama_lock:
            remote_plan = self._remote_applied(instance_ref)
            if remote_plan is None:
                execution_record = self._ollama_executions.get(instance_ref)
                if execution_record is None:
                    raise FleetConflictError("ollama.runtime_not_owned")
                execution, fence = execution_record
                return transport.stop(execution, current_fence=fence)
            if registry.load().generation != expected_generation:
                raise FleetConflictError("control.plan_stale")
            self._assert_remote_resource_fence(remote_plan)
            if self._remote_stopped(instance_ref):
                return None
            try:
                queued = transport.stop_remote(
                    remote_plan.instance,
                    generation=expected_generation,
                    resource_generation=remote_plan.resource_generation,
                    plan_digest=remote_plan.plan_digest,
                    plan_precondition_digest=remote_plan.agent_plan_digest,
                    owner_plan_id=remote_plan.operation_id,
                )
            except AttributeError:
                raise FleetConflictError("ollama.transport_invalid") from None
            if type(queued) is not OperationV1:
                raise FleetConflictError("ollama.transport_invalid")
            self._ollama_remote_operations[queued.id] = ("stop", remote_plan)
            self._record_remote_operation(
                queued,
                action="stop",
                plan=remote_plan,
                agent_plan_digest=remote_plan.plan_digest,
            )
            return queued

    def accept_agent_result(
        self, principal: OperationAgentPrincipalV1, receipt: AgentReceiptV1
    ) -> object:
        """Complete one Ollama receipt after its typed owner fences are checked.

        Unknown effects deliberately complete only the durable agent operation:
        no registry row, readiness cache, or Hive lane is fabricated or retried.
        """

        if (
            type(principal) is not OperationAgentPrincipalV1
            or type(receipt) is not AgentReceiptV1
            or self._agent_operations is None
        ):
            raise FleetConflictError("ollama.transport_invalid")
        with self._ollama_lock:
            managed = self._remote_operation(receipt.operation_id)
            if managed is None:
                raise FleetConflictError("resource.host_response_invalid")
            action, plan, record = managed
            try:
                context = self._agent_operations.validate_completion(principal, receipt)
                queued = self._agent_operations.get(receipt.operation_id)
            except AgentOperationError as error:
                raise FleetConflictError(error.code) from None
            expected_precondition = "sha256:" + (
                cast(str, record.get("agent_plan_digest"))
                if action == "plan" else plan.agent_plan_digest
            )
            if (
                context.get("target_host_ref") != plan.instance.host_ref
                or context.get("registry_generation") != queued.registry_generation
                or queued.kind != "ollama.instance"
                or queued.action != action
                or queued.arguments_digest != record.get("arguments_digest")
                or queued.plan_digest
                != "sha256:" + cast(str, record.get("agent_plan_digest"))
                or context.get("required_registry_generation")
                != queued.registry_generation
                or context.get("resource_generation") != plan.resource_generation
                or context.get("plan_precondition_digest")
                != expected_precondition
                or context.get("envelope_digest")
                != remote_envelope_digest(
                    registry_generation=queued.registry_generation,
                    lease_epoch=cast(int, context.get("required_lease_epoch")),
                    resource_generation=plan.resource_generation,
                    plan_precondition_digest=expected_precondition,
                )
                or receipt.envelope_digest != context.get("envelope_digest")
            ):
                raise FleetConflictError("resource.host_response_invalid")
            if (
                receipt.result.kind != "ollama.instance"
                or receipt.result.action != action
            ):
                raise FleetConflictError("resource.host_response_invalid")
            # The receipt is the durable saga's idempotency key.  Persist it
            # before a registry/lane side effect, then let redelivery resume
            # the exact phase after a process interruption.
            self._prepare_remote_completion(receipt)
            instance_ref: str | None = None
            readiness: OllamaReadinessStatus | None = None
            if receipt.state != "succeeded":
                self._mark_remote_owner_applied(
                    receipt, instance_ref=None, readiness=None
                )
            elif action == "plan":
                self._mark_remote_owner_applied(
                    receipt, instance_ref=None, readiness=None
                )
            elif action == "apply":
                instance_ref = self._accept_remote_apply(plan, receipt)
                self._mark_remote_owner_applied(
                    receipt, instance_ref=instance_ref, readiness=None
                )
            elif action == "probe":
                instance_ref, readiness = self._accept_remote_probe(plan, receipt)
                self._mark_remote_owner_applied(
                    receipt, instance_ref=instance_ref, readiness=readiness
                )
            elif action == "stop":
                instance_ref = self._accept_remote_stop(plan, receipt)
                self._mark_remote_owner_applied(
                    receipt, instance_ref=instance_ref, readiness=None
                )
            else:
                raise FleetConflictError("resource.host_response_invalid")
            completed = self._agent_operations.complete(principal, receipt)
            self._mark_remote_completed(
                receipt, instance_ref=instance_ref, readiness=readiness
            )
            return completed

    def _accept_remote_apply(
        self, plan: _RemoteOllamaPlanV1, receipt: AgentReceiptV1
    ) -> str:
        payload = receipt.result.payload
        if (
            set(payload) != {"instance_ref", "generation"}
            or payload.get("instance_ref") != plan.instance.ref
            or type(payload.get("generation")) is not int
            or payload.get("generation") != plan.registry_generation
        ):
            raise FleetConflictError("resource.host_response_invalid")
        registry, _transport = self._require_ollama()
        current = registry.load()
        running = dataclass_replace(
            plan.instance, lifecycle_state="running", readiness_state="unknown"
        )
        existing = next(
            (item for item in current.instances if item.ref == running.ref), None
        )
        if current.generation == plan.registry_generation:
            pass
        elif current.generation == plan.registry_generation + 1 and existing == running:
            self._ollama_remote_applied[running.ref] = plan
            return running.ref
        else:
            raise FleetConflictError("control.plan_stale")
        instances = tuple(
            running if item.ref == running.ref else item for item in current.instances
        )
        if all(item.ref != running.ref for item in current.instances):
            instances += (running,)
        registry.replace(
            models=current.models,
            instances=instances,
            expected_generation=current.generation,
        )
        self._ollama_remote_applied[running.ref] = plan
        return running.ref

    def _accept_remote_probe(
        self, plan: _RemoteOllamaPlanV1, receipt: AgentReceiptV1
    ) -> tuple[str, OllamaReadinessStatus | None]:
        payload = receipt.result.payload
        try:
            readiness = OllamaReadinessStatus(
                payload["ready"],
                tuple(payload["reason_codes"]),
                payload["process_running"],
                payload["cgroup_member"],
                payload["loopback_endpoint_reachable"],
                tuple(payload["available_model_ids"]),
            )
        except (KeyError, TypeError, ValueError):
            raise FleetConflictError("resource.host_response_invalid") from None
        registry, _transport = self._require_ollama()
        current = registry.load()
        instance = next((item for item in current.instances if item.ref == plan.instance.ref), None)
        if instance is None:
            raise FleetConflictError("ollama.runtime_not_owned")
        models = {model.ref: model for model in current.models}
        selected = tuple(models.get(ref) for ref in instance.selected_model_refs)
        ready = (
            readiness.ready
            and readiness.process_running
            and readiness.cgroup_member
            and readiness.loopback_endpoint_reachable
            and all(model is not None for model in selected)
            and all(
                model.provider_model_id in readiness.available_model_ids
                for model in selected
                if model is not None
            )
        )
        updated = dataclass_replace(
            instance,
            lifecycle_state="running" if readiness.process_running else "failed",
            readiness_state="ready" if ready else "not_ready",
        )
        if updated != instance:
            registry.replace(
                models=current.models,
                instances=tuple(
                    updated if item.ref == updated.ref else item
                    for item in current.instances
                ),
                expected_generation=current.generation,
            )
        if ready:
            self._ollama_ready[updated.ref] = readiness
        else:
            self._ollama_ready.pop(updated.ref, None)
        return updated.ref, readiness if ready else None

    def _accept_remote_stop(
        self, plan: _RemoteOllamaPlanV1, receipt: AgentReceiptV1
    ) -> str:
        if receipt.result.payload != {"stopped": True}:
            raise FleetConflictError("resource.host_response_invalid")
        registry, _transport = self._require_ollama()
        current = registry.load()
        instance = next((item for item in current.instances if item.ref == plan.instance.ref), None)
        if instance is None:
            raise FleetConflictError("ollama.runtime_not_owned")
        stopped = dataclass_replace(
            instance, lifecycle_state="stopped", readiness_state="unknown"
        )
        if stopped != instance:
            registry.replace(
                models=current.models,
                instances=tuple(
                    stopped if item.ref == stopped.ref else item
                    for item in current.instances
                ),
                expected_generation=current.generation,
            )
        self._ollama_ready.pop(stopped.ref, None)
        self._ollama_remote_applied.pop(stopped.ref, None)
        return stopped.ref

    def _ensure_layout(self) -> None:
        self._io.ensure_dir(self._paths.root)
        self._io.ensure_dir(self._paths.secrets)

    def _load_registry(self) -> FleetSnapshot | FleetSnapshotV2:
        self._ensure_layout()
        text = self._io.read_text(
            self._paths.registry,
            MAX_REGISTRY_BYTES,
            "could_not_read_fleet_registry",
        )
        if text is None:
            return FleetSnapshot(1, 1, (), ())
        try:
            raw = json.loads(text)
        except (json.JSONDecodeError, UnicodeError) as exc:
            raise ValueError("invalid_fleet_registry") from exc
        return normalize_fleet_document(raw)

    def _write_registry(self, snapshot: FleetSnapshot | FleetSnapshotV2) -> FleetSnapshot | FleetSnapshotV2:
        document = fleet_document(snapshot)
        text = json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        self._io.replace_text(self._paths.registry, text)
        stored = self._load_registry()
        if stored != snapshot:
            raise ValueError("fleet_registry_write_verification_failed")
        return stored

    @staticmethod
    def _parse_time(value: object) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str) or not 1 <= len(value) <= 40:
            raise ValueError("invalid_fleet_limits")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("invalid_fleet_limits") from None
        if parsed.tzinfo is None:
            raise ValueError("invalid_fleet_limits")
        return value

    def _quarantine_limits(self, reason: str = "invalid_fleet_limits") -> None:
        """Record a redacted limits failure without overwriting the WAL journal."""

        marker = self._paths.recovery.with_name("limits.recovery.json")
        try:
            self._io.replace_text(
                marker,
                json.dumps({"schema_version": 1, "kind": "fleet_limits_quarantine", "reason": reason}) + "\n",
            )
        except Exception:
            pass

    def _load_limits(self) -> dict[str, dict[str, str | None]]:
        self._ensure_layout()
        try:
            text = self._io.read_text(
                self._paths.limits,
                MAX_LIMIT_BYTES,
                "could_not_read_fleet_limits",
            )
            if text is None:
                return {}
            raw = json.loads(text)
            if (
                not isinstance(raw, dict)
                or set(raw) != {"schema_version", "accounts"}
                or raw.get("schema_version") != 1
                or not isinstance(raw.get("accounts"), dict)
            ):
                raise ValueError("invalid_fleet_limits")
            entries: dict[str, dict[str, str | None]] = {}
            for account_id, value in raw["accounts"].items():
                if (
                    not isinstance(account_id, str)
                    or not _ACCOUNT_ID_RE.fullmatch(account_id)
                    or not isinstance(value, dict)
                    or set(value) != {"reset_at_utc", "reason"}
                ):
                    raise ValueError("invalid_fleet_limits")
                reason = value.get("reason")
                if not isinstance(reason, str) or not _LIMIT_REASON_RE.fullmatch(reason):
                    raise ValueError("invalid_fleet_limits")
                entries[account_id] = {
                    "reset_at_utc": self._parse_time(value.get("reset_at_utc")),
                    "reason": reason,
                }
            return entries
        except Exception:
            self._quarantine_limits()
            if self._read_only:
                raise ValueError("invalid_fleet_limits") from None
            return {}

    def _write_limits(self, entries: dict[str, dict[str, str | None]]) -> None:
        document = {"schema_version": 1, "accounts": entries}
        text = json.dumps(document, indent=2, sort_keys=True) + "\n"
        self._io.replace_text(self._paths.limits, text)
        if self._load_limits() != entries:
            raise ValueError("fleet_limits_write_verification_failed")

    def _quarantine_rate_limits(self, reason: str = "invalid_gemini_rate_limits") -> None:
        marker = self._paths.recovery.with_name("rate-limits.recovery.json")
        try:
            self._io.replace_text(
                marker,
                json.dumps({"schema_version": 1, "kind": "gemini_rate_limits_quarantine", "reason": reason}) + "\n",
            )
        except Exception:
            pass

    def _parse_rate_state(self, state: object) -> dict[str, object]:
        required = {
            "next_allowed_at_utc",
            "cooldown_until_utc",
            "in_flight",
            "consecutive_429",
        }
        if not isinstance(state, dict) or set(state) != required:
            raise ValueError("invalid_gemini_rate_limits")
        next_allowed = self._parse_time(state.get("next_allowed_at_utc"))
        cooldown = self._parse_time(state.get("cooldown_until_utc"))
        if next_allowed is None:
            raise ValueError("invalid_gemini_rate_limits")
        in_flight = state.get("in_flight")
        if in_flight is not None:
            if (
                not isinstance(in_flight, dict)
                or set(in_flight) != {"reservation_id", "expires_at_utc"}
                or not isinstance(in_flight.get("reservation_id"), str)
                or not re.fullmatch(r"[0-9a-f]{32}", in_flight["reservation_id"])
                or self._parse_time(in_flight.get("expires_at_utc")) is None
            ):
                raise ValueError("invalid_gemini_rate_limits")
            in_flight = {
                "reservation_id": in_flight["reservation_id"],
                "expires_at_utc": in_flight["expires_at_utc"],
            }
        consecutive = state.get("consecutive_429")
        if isinstance(consecutive, bool) or not isinstance(consecutive, int) or not 0 <= consecutive <= 32:
            raise ValueError("invalid_gemini_rate_limits")
        return {
            "next_allowed_at_utc": next_allowed,
            "cooldown_until_utc": cooldown,
            "in_flight": in_flight,
            "consecutive_429": consecutive,
        }

    def _load_rate_limits(self) -> dict[str, dict[str, object]]:
        self._ensure_layout()
        try:
            text = self._io.read_text(
                self._paths.rate_limits,
                MAX_RATE_LIMIT_BYTES,
                "could_not_read_gemini_rate_limits",
            )
            if text is None:
                return {}
            raw = json.loads(text)
            if not isinstance(raw, dict) or set(raw) != {"schema_version", "accounts"} or not isinstance(raw.get("accounts"), dict):
                raise ValueError("invalid_gemini_rate_limits")
            version = raw.get("schema_version")
            if not isinstance(version, int):
                raise ValueError("invalid_gemini_rate_limits")

            entries: dict[str, dict[str, object]] = {}
            if version == 1:
                required = {"next_allowed_at_utc", "cooldown_until_utc", "in_flight", "consecutive_429"}
                for account_id, value in raw["accounts"].items():
                    if (
                        not isinstance(account_id, str)
                        or not _ACCOUNT_ID_RE.fullmatch(account_id)
                        or not isinstance(value, dict)
                        or set(value) != required
                    ):
                        raise ValueError("invalid_gemini_rate_limits")
                    state = self._parse_rate_state(value)
                    entries[account_id] = {**state, "models": {}}
            elif version == 2:
                account_keys = {
                    "next_allowed_at_utc",
                    "cooldown_until_utc",
                    "in_flight",
                    "consecutive_429",
                    "models",
                }
                for account_id, value in raw["accounts"].items():
                    if (
                        not isinstance(account_id, str)
                        or not _ACCOUNT_ID_RE.fullmatch(account_id)
                        or not isinstance(value, dict)
                        or set(value) != account_keys
                    ):
                        raise ValueError("invalid_gemini_rate_limits")
                    state = self._parse_rate_state(
                        {
                            "next_allowed_at_utc": value.get("next_allowed_at_utc"),
                            "cooldown_until_utc": value.get("cooldown_until_utc"),
                            "in_flight": value.get("in_flight"),
                            "consecutive_429": value.get("consecutive_429"),
                        },
                    )
                    models = value.get("models")
                    if not isinstance(models, dict):
                        raise ValueError("invalid_gemini_rate_limits")
                    normalized_models: dict[str, dict[str, object]] = {}
                    for model_key, model_state in models.items():
                        if not isinstance(model_key, str) or self._normalize_gemini_model(model_key) != model_key:
                            raise ValueError("invalid_gemini_rate_limits")
                        normalized_models[model_key] = self._parse_rate_state(model_state)
                    state["models"] = normalized_models
                    entries[account_id] = state
            else:
                raise ValueError("invalid_gemini_rate_limits")
            return entries
        except Exception:
            self._quarantine_rate_limits()
            raise ValueError("invalid_gemini_rate_limits") from None

    def _write_rate_limits(self, entries: dict[str, dict[str, object]]) -> None:
        account_keys = {
            "next_allowed_at_utc",
            "cooldown_until_utc",
            "in_flight",
            "consecutive_429",
            "models",
        }
        normalized: dict[str, dict[str, object]] = {}
        for account_id, entry in entries.items():
            if (
                not isinstance(account_id, str)
                or not _ACCOUNT_ID_RE.fullmatch(account_id)
                or not isinstance(entry, dict)
                or set(entry) != account_keys
            ):
                raise ValueError("invalid_gemini_rate_limits")
            account_state = self._parse_rate_state({key: entry[key] for key in account_keys if key != "models"})
            models = entry["models"]
            if not isinstance(models, dict):
                raise ValueError("invalid_gemini_rate_limits")
            normalized_models: dict[str, dict[str, object]] = {}
            for model_key, model_entry in models.items():
                if not isinstance(model_key, str) or self._normalize_gemini_model(model_key) != model_key:
                    raise ValueError("invalid_gemini_rate_limits")
                normalized_models[model_key] = self._parse_rate_state(model_entry)
            normalized[account_id] = {**account_state, "models": normalized_models}
        document = {"schema_version": 2, "accounts": normalized}
        text = json.dumps(document, indent=2, sort_keys=True) + "\n"
        self._io.replace_text(self._paths.rate_limits, text)
        if self._load_rate_limits() != normalized:
            raise ValueError("gemini_rate_limits_write_verification_failed")

    def _load_usage(self) -> dict[str, list[dict[str, object]]]:
        self._ensure_layout()
        try:
            text = self._io.read_text(self._paths.usage, MAX_USAGE_BYTES, "could_not_read_gemini_usage")
            if text is None:
                return {}
            raw = json.loads(text)
            if not isinstance(raw, dict) or raw.get("schema_version") != 1 or not isinstance(raw.get("accounts"), dict):
                raise ValueError("invalid_gemini_usage")
            result: dict[str, list[dict[str, object]]] = {}
            for account_id, events in raw["accounts"].items():
                if not isinstance(account_id, str) or not _ACCOUNT_ID_RE.fullmatch(account_id) or not isinstance(events, list):
                    raise ValueError("invalid_gemini_usage")
                clean: list[dict[str, object]] = []
                for event in events:
                    if not isinstance(event, dict):
                        raise ValueError("invalid_gemini_usage")
                    timestamp = event.get("at_utc")
                    if self._parse_time(timestamp) is None:
                        raise ValueError("invalid_gemini_usage")
                    model = event.get("model")
                    if not isinstance(model, str) or not 1 <= len(model) <= 200:
                        raise ValueError("invalid_gemini_usage")
                    for key in ("input_tokens", "output_tokens", "tool_call_count"):
                        value = event.get(key, 0)
                        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 2**63 - 1:
                            raise ValueError("invalid_gemini_usage")
                    status = event.get("status")
                    if not isinstance(status, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", status):
                        raise ValueError("invalid_gemini_usage")
                    gate_action = event.get("gate_action")
                    if gate_action is not None and gate_action not in {
                        "allow", "defer_until", "rotate_account", "rotate_model", "reject",
                    }:
                        raise ValueError("invalid_gemini_usage")
                    gate_code = event.get("gate_code")
                    if gate_code is not None and gate_code not in GEMINI_GATE_DIAGNOSTICS:
                        raise ValueError("invalid_gemini_usage")
                    quota_scope = event.get("quota_scope")
                    quota_retry_after_seconds = event.get("quota_retry_after_seconds")
                    if not isinstance(quota_scope, str) and quota_scope is not None:
                        raise ValueError("invalid_gemini_usage")
                    if quota_scope is None:
                        quota_scope = None
                        quota_retry_after_seconds = None
                    elif quota_scope not in _USAGE_QUOTA_SCOPES:
                        raise ValueError("invalid_gemini_usage")
                    elif quota_retry_after_seconds is not None:
                        if (
                            isinstance(quota_retry_after_seconds, bool)
                            or not isinstance(quota_retry_after_seconds, int)
                            or quota_retry_after_seconds <= 0
                            or quota_retry_after_seconds > _GEMINI_MAX_USAGE_QUOTA_RETRY_SECONDS
                        ):
                            raise ValueError("invalid_gemini_usage")
                    else:
                        quota_retry_after_seconds = None
                    reset_at = event.get("next_reset_at_utc")
                    if reset_at is not None and self._parse_time(reset_at) is None:
                        raise ValueError("invalid_gemini_usage")
                    clean.append({
                        "at_utc": timestamp,
                        "model": model,
                        "input_tokens": event.get("input_tokens", 0),
                        "output_tokens": event.get("output_tokens", 0),
                        "tool_call_count": event.get("tool_call_count", 0),
                        "status": status,
                        "gate_action": gate_action,
                        "gate_code": gate_code,
                        "quota_scope": quota_scope,
                        "quota_retry_after_seconds": quota_retry_after_seconds,
                        "next_reset_at_utc": reset_at,
                    })
                result[account_id] = clean[-2000:]
            return result
        except Exception:
            marker = self._paths.recovery.with_name("usage.recovery.json")
            try:
                self._io.replace_text(
                    marker,
                    json.dumps({"schema_version": 1, "kind": "gemini_usage_quarantine"}) + "\n",
                )
            except Exception:
                pass
            raise ValueError("invalid_gemini_usage") from None

    def _write_usage(self, entries: dict[str, list[dict[str, object]]]) -> None:
        document = {"schema_version": 1, "accounts": entries}
        text = json.dumps(document, indent=2, sort_keys=True) + "\n"
        self._io.replace_text(self._paths.usage, text)
        if self._load_usage() != entries:
            raise ValueError("gemini_usage_write_verification_failed")

    @staticmethod
    def gemini_billing_group(account_id: str) -> str:
        match = re.fullmatch(r"the-hive-(\d+)", account_id)
        if match:
            number = int(match.group(1))
            return f"the-hive-account-{((number - 1) // 10) + 1}"
        return account_id

    @staticmethod
    def _normalize_gemini_model(model: str | None) -> str | None:
        if model is None:
            return None
        try:
            return validate_gemini_probe_model(model)
        except FleetRunnerError:
            return None

    @classmethod
    def gemini_quota_limits(cls, tier: str, model: str | None) -> dict[str, int] | None:
        """Return model-specific limits from the supplied AI Studio snapshots."""

        if not isinstance(tier, str):
            return None
        model_key = cls._normalize_gemini_model(model)
        limits = GEMINI_QUOTA_SNAPSHOTS.get(tier, {}).get(model_key or "")
        return dict(limits) if limits is not None else None

    @classmethod
    def gemini_quota_profile(
        cls,
        account_id: str,
        *,
        model: str | None = None,
    ) -> dict[str, object]:
        """Return billing metadata and model limits without guessing."""

        billing_group = cls.gemini_billing_group(account_id)
        tier = GEMINI_PROJECT_BILLING_TIERS.get(account_id, "unknown")
        tier1 = tier == "tier1"
        model_key = cls._normalize_gemini_model(model)
        project_limits = GEMINI_PROJECT_QUOTA_SNAPSHOTS.get(account_id, {})
        model_limits = project_limits.get(model_key or "")
        limits_by_model = {
            name: dict(values)
            for name, values in project_limits.items()
        }
        return {
            "billing_group": billing_group,
            "billing_tier": tier,
            "billing_tier_source": (
                GEMINI_QUOTA_SNAPSHOT_SOURCE if tier != "unknown" else "not_confirmed"
            ),
            "provider_quota_source": (
                GEMINI_QUOTA_SNAPSHOT_SOURCE if model_limits is not None else "ai_studio_dashboard"
            ),
            "quota_snapshot_source": GEMINI_QUOTA_SNAPSHOT_SOURCE if limits_by_model else None,
            "quota_model": model_key,
            "limits_by_model": limits_by_model,
            "rpm_limit": model_limits.get("rpm") if model_limits is not None else None,
            "tpm_limit": model_limits.get("tpm") if model_limits is not None else None,
            "rpd_limit": model_limits.get("rpd") if model_limits is not None else None,
            "spend_rate_limit_usd_per_10_minutes": (
                GEMINI_TIER1_SPEND_RATE_LIMIT_USD_PER_10_MINUTES if tier1 else None
            ),
            "billing_cap_usd_per_month": (
                GEMINI_TIER1_BILLING_CAP_USD_PER_MONTH if tier1 else None
            ),
            "local_request_interval_seconds": (
                GEMINI_TIER1_LOCAL_REQUEST_INTERVAL_SECONDS if tier1
                else GEMINI_MIN_REQUEST_INTERVAL_SECONDS
            ),
            "quota_scope": "project",
            "billing_scope": "billing_account",
        }

    def project_limit_identity(
        self,
        account_id: str,
        *,
        model: str | None = None,
    ) -> dict[str, object]:
        """Expose the quota scope explicitly.

        Gemini RPM/TPM/RPD counters are per project.  Billing tier and spend
        caps can additionally be shared by the billing group.  The local
        request limiter must therefore never use this group as its key.
        """

        snapshot = self.load()
        account = next((item for item in snapshot.accounts if item.account_id == account_id), None)
        billing_group = (
            account.billing_group
            if account is not None and account.billing_group
            else self.gemini_billing_group(account_id)
        )
        quota = self.gemini_quota_profile(account_id, model=model)
        return {
            "project_id": account_id,
            "rpm_tpm_rpd_scope": "project",
            "spend_and_tier_scope": "billing_account",
            **quota,
            "billing_group": billing_group,
        }

    def record_gemini_usage(
        self,
        account_id: str,
        *,
        model: str,
        input_tokens: int | None = None,
        output_tokens: int | None = None,
        tool_call_count: int | None = None,
        status: str = "completed",
        gate_action: str | None = None,
        gate_code: str | None = None,
        next_reset_at_utc: str | None = None,
        quota_observation: ProviderErrorQuotaObservation | None = None,
    ) -> dict[str, object]:
        if not isinstance(account_id, str) or not _ACCOUNT_ID_RE.fullmatch(account_id):
            raise ValueError("invalid_account")
        if not isinstance(model, str) or not 1 <= len(model) <= 200:
            raise ValueError("invalid_gemini_usage")
        if status not in {"completed", "failed", "cancelled", "timeout", "probe", "rate_limited"}:
            raise ValueError("invalid_gemini_usage")
        input_value = 0 if input_tokens is None else input_tokens
        output_value = 0 if output_tokens is None else output_tokens
        tool_call_value = 0 if tool_call_count is None else tool_call_count
        if (
            isinstance(input_value, bool) or not isinstance(input_value, int) or input_value < 0
            or isinstance(output_value, bool) or not isinstance(output_value, int) or output_value < 0
            or isinstance(tool_call_value, bool) or not isinstance(tool_call_value, int) or tool_call_value < 0
        ):
            raise ValueError("invalid_gemini_usage")
        if gate_action is not None and gate_action not in {
            "allow", "defer_until", "rotate_account", "rotate_model", "reject",
        }:
            raise ValueError("invalid_gemini_usage")
        if gate_code is not None and gate_code not in GEMINI_GATE_DIAGNOSTICS:
            raise ValueError("invalid_gemini_usage")
        if quota_observation is not None and (
            quota_observation.scope not in _USAGE_QUOTA_SCOPES
            or not isinstance(quota_observation.retry_after_seconds, int | type(None))
            or isinstance(quota_observation.retry_after_seconds, bool)
            or (quota_observation.retry_after_seconds is not None
                and (
                    quota_observation.retry_after_seconds <= 0
                    or quota_observation.retry_after_seconds > _GEMINI_MAX_USAGE_QUOTA_RETRY_SECONDS
                ))
        ):
            raise ValueError("invalid_gemini_usage")
        quota_scope = quota_observation.scope if quota_observation is not None else None
        quota_retry_after_seconds = quota_observation.retry_after_seconds if quota_observation is not None else None
        if next_reset_at_utc is not None and self._parse_time(next_reset_at_utc) is None:
            raise ValueError("invalid_gemini_usage")
        if (
            quota_retry_after_seconds is not None
            and isinstance(quota_retry_after_seconds, int)
            and quota_retry_after_seconds > _GEMINI_MAX_USAGE_QUOTA_RETRY_SECONDS
        ):
            raise ValueError("invalid_gemini_usage")
        with self._io.lock():
            now = self._rate_now()
            cutoff = now - timedelta(hours=24)
            entries = self._load_usage()
            events = []
            for event in entries.get(account_id, []):
                try:
                    at = datetime.fromisoformat(str(event["at_utc"]).replace("Z", "+00:00"))
                except (KeyError, TypeError, ValueError):
                    continue
                if at.tzinfo is not None and at.astimezone(timezone.utc) >= cutoff:
                    events.append(event)
            event = {
                "at_utc": self._rate_text(now),
                "model": model,
                "input_tokens": input_value,
                "output_tokens": output_value,
                "tool_call_count": tool_call_value,
                "status": status,
                "gate_action": gate_action,
                "gate_code": gate_code,
                "quota_scope": quota_scope,
                "quota_retry_after_seconds": quota_retry_after_seconds,
                "next_reset_at_utc": next_reset_at_utc,
            }
            events.append(event)
            entries[account_id] = events[-2000:]
            self._write_usage(entries)
        return self.gemini_usage_status(account_id)

    def gemini_usage_status(self, account_id: str, *, model: str | None = None) -> dict[str, object]:
        snapshot = self.load()
        now = self._rate_now()
        events = self._load_usage().get(account_id, [])
        recent_minute: list[dict[str, object]] = []
        recent_day: list[dict[str, object]] = []
        for event in events:
            try:
                at = datetime.fromisoformat(str(event["at_utc"]).replace("Z", "+00:00"))
            except (KeyError, TypeError, ValueError):
                continue
            if at.tzinfo is None:
                continue
            age = (now - at.astimezone(timezone.utc)).total_seconds()
            if 0 <= age < 60:
                recent_minute.append(event)
            if 0 <= age < 86400:
                recent_day.append(event)
        account = next((item for item in snapshot.accounts if item.account_id == account_id), None)
        probe_age = None
        probe_state = "unknown"
        if account is not None and account.last_probe_at_utc is not None:
            try:
                probed = datetime.fromisoformat(account.last_probe_at_utc.replace("Z", "+00:00"))
                probe_age = max(0, int((now - probed.astimezone(timezone.utc)).total_seconds()))
                probe_state = "fresh" if self._probe_is_fresh(account.last_probe_at_utc) else "stale"
            except (TypeError, ValueError, AttributeError):
                probe_state = "invalid"
        identity = self.project_limit_identity(account_id, model=model)
        observed = {
            "rpm": len(recent_minute),
            # Google defines TPM as input tokens per minute.  Output tokens
            # remain visible separately and are not folded into TPM.
            "tpm": sum(int(event.get("input_tokens", 0)) for event in recent_minute),
            "rpd": len(recent_day),
        }
        model_evaluations: dict[str, dict[str, object]] = {}
        model_names = {
            str(event.get("model"))
            for event in recent_day
            if isinstance(event.get("model"), str) and event.get("model")
        }
        if isinstance(model, str) and model:
            model_names.add(model)
        model_names = sorted(model_names)
        for model in model_names:
            model_minute = [event for event in recent_minute if event.get("model") == model]
            model_day = [event for event in recent_day if event.get("model") == model]
            model_observed = {
                "rpm": len(model_minute),
                "tpm": sum(int(event.get("input_tokens", 0)) for event in model_minute),
                "rpd": len(model_day),
                "tool_call_count": sum(int(event.get("tool_call_count", 0)) for event in model_day),
            }
            model_profile = self.gemini_quota_profile(account_id, model=model)
            model_limits = {
                "rpm": model_profile.get("rpm_limit"),
                "tpm": model_profile.get("tpm_limit"),
                "rpd": model_profile.get("rpd_limit"),
            }
            resets_at_utc = {
                "rpm": self._quota_window_reset(
                    model_minute, seconds=60, limit=model_limits["rpm"], metric="rpm",
                ),
                "tpm": self._quota_window_reset(
                    model_minute, seconds=60, limit=model_limits["tpm"], metric="tpm",
                ),
                "rpd": self._quota_window_reset(
                    model_day, seconds=86400, limit=model_limits["rpd"], metric="rpd",
                ),
            }
            utilization: dict[str, float | None] = {}
            for metric, value in model_observed.items():
                if metric == "tool_call_count":
                    continue
                limit = model_limits[metric]
                if isinstance(limit, (int, float)) and not isinstance(limit, bool) and limit > 0:
                    utilization[metric] = round(float(value) / float(limit) * 100, 2)
                else:
                    utilization[metric] = None
            model_quota_observation: dict[str, object] | None = None
            if model_day:
                for candidate_event in reversed(model_day):
                    scope = candidate_event.get("quota_scope")
                    if scope not in _USAGE_QUOTA_SCOPES:
                        continue
                    retry_after_seconds = candidate_event.get("quota_retry_after_seconds")
                    if (
                        retry_after_seconds is None
                        or (
                            isinstance(retry_after_seconds, int)
                            and not isinstance(retry_after_seconds, bool)
                        )
                    ):
                        model_quota_observation = {
                            "scope": scope,
                            "retry_after_seconds": retry_after_seconds,
                            "at_utc": candidate_event.get("at_utc"),
                        }
                    break
            model_evaluations[model] = {
                "model": model,
                "observed": model_observed,
                "limits": model_limits,
                "resets_at_utc": resets_at_utc,
                "utilization_percent": utilization,
                "state": (
                    "limits_unknown_dashboard_required"
                    if any(value is None for value in model_limits.values())
                    else "within_limits"
                ),
                "limits_source": model_profile["provider_quota_source"],
                "quota_observation": model_quota_observation,
            }
        if model is not None and model in model_evaluations:
            quota_evaluation = model_evaluations[model]
            quota_evaluation["scope"] = identity["quota_scope"]
        elif len(model_evaluations) == 1:
            quota_evaluation: dict[str, object] = next(iter(model_evaluations.values()))
            quota_evaluation["scope"] = identity["quota_scope"]
        elif model_evaluations:
            quota_evaluation = {
                "state": "mixed_models",
                "scope": identity["quota_scope"],
                "limits_source": identity["provider_quota_source"],
                "models": model_evaluations,
            }
        else:
            quota_evaluation = {
                "state": "model_required",
                "scope": identity["quota_scope"],
                "limits_source": identity["provider_quota_source"],
                "limits_by_model": identity["limits_by_model"],
            }
        return {
            "account_id": account_id,
            **identity,
            "probe_state": probe_state,
            "probe_age_seconds": probe_age,
            "rpm_observed": len(recent_minute),
            "tpm_observed": observed["tpm"],
            "output_tokens_per_minute_observed": sum(int(event.get("output_tokens", 0)) for event in recent_minute),
            "tool_call_count_24h": sum(int(event.get("tool_call_count", 0)) for event in recent_day),
            "rpd_observed": len(recent_day),
            "input_tokens_24h": sum(int(event.get("input_tokens", 0)) for event in recent_day),
            "output_tokens_24h": sum(int(event.get("output_tokens", 0)) for event in recent_day),
            "last_request_at_utc": events[-1].get("at_utc") if events else None,
            "event_count_24h": len(recent_day),
            "last_gate": (
                {
                    "action": events[-1].get("gate_action"),
                    "code": events[-1].get("gate_code"),
                }
                if events and events[-1].get("gate_action") is not None and events[-1].get("gate_code") is not None
                else None
            ),
            "next_known_reset_at_utc": events[-1].get("next_reset_at_utc") if events else None,
            "quota_evaluation": quota_evaluation,
            "spend_evaluation": {
                "state": "billing_export_required",
                "scope": identity["billing_scope"],
                "limit_usd_per_10_minutes": identity["spend_rate_limit_usd_per_10_minutes"],
                "billing_cap_usd_per_month": identity["billing_cap_usd_per_month"],
                "observed_spend_usd": None,
            },
            "raw_output": "not_returned",
        }

    def gemini_usage_watchdog(self) -> dict[str, object]:
        snapshot = self.load()
        accounts = [
            self.gemini_usage_status(account.account_id)
            for account in snapshot.accounts
            if account.provider.value == "gemini_api"
        ]
        stale = [item["account_id"] for item in accounts if item["probe_state"] in {"stale", "unknown", "invalid"}]
        return {
            "provider": "gemini_api",
            "account_count": len(accounts),
            "accounts": accounts,
            "stale_or_unknown_accounts": stale,
            "state": "ready" if not stale else "probe_deferred_until_invocation",
            "probe_policy": "probe_once_when_invocation_admission_sees_stale_or_unknown",
            "limits_source": "observed_project_counters; RPM/TPM/RPD caps must be supplied by the AI Studio dashboard",
            "recent_events": self.gemini_event_status(),
            "raw_output": "not_returned",
        }

    def gemini_event_status(self, limit: int = 20) -> list[dict[str, object]]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("invalid_gemini_event_limit")
        try:
            text = self._io.read_text(self._paths.events, MAX_EVENT_BYTES, "could_not_read_gemini_events") or ""
        except Exception:
            return []
        result: list[dict[str, object]] = []
        for line in text.splitlines()[-limit:]:
            try:
                value = json.loads(line)
            except (TypeError, UnicodeDecodeError, json.JSONDecodeError):
                continue
            if isinstance(value, dict):
                value.pop("raw_output", None)
                result.append(value)
        return result

    def record_gemini_event(
        self,
        *,
        event_type: str,
        agent_id: str | None,
        account_id: str | None,
        assignment_id: str | None,
        status: str,
        reason: str | None = None,
        model: str | None = None,
        input_tokens: int | None = None,
        output_tokens: int | None = None,
        tool_call_count: int | None = None,
        gate_action: str | None = None,
        gate_code: str | None = None,
        next_reset_at_utc: str | None = None,
        diagnostic_code: ProbeDiagnosticCode | None = None,
        endpoint_role: ProbeEndpointRole | None = None,
        http_class: ProbeHttpClass | None = None,
        process_phase: ProbeProcessPhase | None = None,
        process_output_shape: ProbeOutputShape | None = None,
        process_stdout_shape: ProbeStdoutShape | None = None,
        process_stdout_event_class: ProbeStdoutEventClass | None = None,
        process_stdout_error_seen: bool | None = None,
    ) -> dict[str, object]:
        """Append a bounded, redacted Gemini event for master/dispatcher status."""

        if self._read_only:
            return {"recorded": False, "reason": "read_only"}
        normalized_diagnostic_code = normalize_gemini_probe_diagnostic_code(diagnostic_code)
        normalized_endpoint_role = endpoint_role if endpoint_role == "generate_content" else None
        normalized_http_class = (
            http_class
            if isinstance(http_class, str) and http_class in {"2xx", "4xx", "5xx", "transport"}
            else None
        )
        normalized_process_phase = normalize_gemini_probe_process_phase(process_phase)
        normalized_process_output_shape = FleetService._normalize_probe_output_shape_for_timeout(
            normalized_diagnostic_code,
            normalized_process_phase,
            process_output_shape,
        )
        normalized_process_stdout_shape = FleetService._normalize_probe_stdout_shape_for_timeout(
            normalized_diagnostic_code,
            normalized_process_phase,
            process_stdout_shape,
        )
        normalized_process_stdout_event_class = normalize_gemini_probe_stdout_event_class(
            process_stdout_event_class,
        )
        normalized_process_stdout_error_seen = (
            process_stdout_error_seen if isinstance(process_stdout_error_seen, bool) else None
        )
        values = {
            "event_type": event_type,
            "agent_id": agent_id,
            "account_id": account_id,
            "assignment_id": assignment_id,
            "status": status,
            "reason": _redacted_gemini_event_reason(reason),
            "model": model,
            "input_tokens": input_tokens or 0,
            "output_tokens": output_tokens or 0,
            "tool_call_count": tool_call_count or 0,
            "gate_action": gate_action,
            "gate_code": gate_code,
            "next_reset_at_utc": next_reset_at_utc,
        }
        if normalized_diagnostic_code is not None:
            values["diagnostic_code"] = normalized_diagnostic_code
        if normalized_endpoint_role is not None:
            values["endpoint_role"] = normalized_endpoint_role
        if normalized_http_class is not None:
            values["http_class"] = normalized_http_class
        if normalized_process_phase is not None:
            values["process_phase"] = normalized_process_phase
        if normalized_process_output_shape is not None:
            values["process_output_shape"] = normalized_process_output_shape
        if normalized_process_stdout_shape is not None:
            values["process_stdout_shape"] = normalized_process_stdout_shape
            if (
                normalized_process_stdout_shape == "gemini_probe_stdout_jsonl_incomplete"
                and normalized_process_stdout_event_class is not None
                and normalized_process_stdout_error_seen is not None
            ):
                values["process_stdout_event_class"] = normalized_process_stdout_event_class
                values["process_stdout_error_seen"] = normalized_process_stdout_error_seen
        for key in ("event_type", "status"):
            value = values[key]
            if not isinstance(value, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", value):
                raise ValueError("invalid_gemini_event")
        for key in ("agent_id", "account_id", "assignment_id", "reason", "model"):
            value = values[key]
            if value is not None and (not isinstance(value, str) or not 1 <= len(value) <= 300):
                raise ValueError("invalid_gemini_event")
        for key in ("input_tokens", "output_tokens", "tool_call_count"):
            value = values[key]
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 2**63 - 1:
                raise ValueError("invalid_gemini_event")
        if gate_action is not None and gate_action not in {
            "allow", "defer_until", "rotate_account", "rotate_model", "reject",
        }:
            raise ValueError("invalid_gemini_event")
        if gate_code is not None and gate_code not in GEMINI_GATE_DIAGNOSTICS:
            raise ValueError("invalid_gemini_event")
        if next_reset_at_utc is not None and self._parse_time(next_reset_at_utc) is None:
            raise ValueError("invalid_gemini_event")
        with self._io.lock():
            try:
                existing = self._io.read_text(self._paths.events, MAX_EVENT_BYTES, "could_not_read_gemini_events") or ""
            except Exception:
                existing = ""
            lines = [line for line in existing.splitlines() if line.strip()][-511:]
            entry = {
                "at_utc": self._rate_text(self._rate_now()),
                **values,
                "raw_output": "not_returned",
            }
            lines.append(json.dumps(entry, sort_keys=True, ensure_ascii=False))
            text = "\n".join(lines) + "\n"
            if len(text.encode("utf-8")) > MAX_EVENT_BYTES:
                lines = lines[-256:]
                text = "\n".join(lines) + "\n"
            self._io.replace_text(self._paths.events, text)
        return {"recorded": True, "event_type": event_type, "status": status}

    def _rate_now(self) -> datetime:
        now = self._io.utc_now()
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise ValueError("invalid_utc_clock")
        return now.astimezone(timezone.utc)

    @staticmethod
    def _rate_text(value: datetime) -> str:
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    @classmethod
    def _quota_window_reset(
        cls,
        events: list[dict[str, object]],
        *,
        seconds: int,
        limit: object,
        metric: str,
    ) -> str | None:
        if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
            return None
        observations: list[tuple[datetime, int]] = []
        for event in events:
            try:
                at = datetime.fromisoformat(str(event["at_utc"]).replace("Z", "+00:00"))
            except (KeyError, TypeError, ValueError):
                continue
            if at.tzinfo is not None:
                weight = int(event.get("input_tokens", 0)) if metric == "tpm" else 1
                observations.append((at.astimezone(timezone.utc), weight))
        observed = sum(weight for _at, weight in observations)
        if observed < limit:
            return None
        for at, weight in sorted(observations):
            observed -= weight
            if observed < limit:
                return cls._rate_text(at + timedelta(seconds=seconds))
        return None

    @staticmethod
    def _retry_after(now: datetime, *values: str | None) -> int:
        deadlines: list[datetime] = []
        for value in values:
            if value is None:
                continue
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                continue
            if parsed.tzinfo is not None and parsed > now:
                deadlines.append(parsed.astimezone(timezone.utc))
        if not deadlines:
            return 0
        return max(1, int(max((item - now).total_seconds() for item in deadlines) + 0.999))

    @staticmethod
    def _latest_deadline(now: datetime, *values: str | None) -> str | None:
        deadlines: list[datetime] = []
        for value in values:
            if value is None:
                continue
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                continue
            if parsed.tzinfo is not None and parsed.astimezone(timezone.utc) > now:
                deadlines.append(parsed.astimezone(timezone.utc))
        return FleetService._rate_text(max(deadlines)) if deadlines else None

    def reserve_gemini_request(self, account_id: str, *, model: str | None = None) -> GeminiRequestReservation:
        if self._read_only:
            raise FleetRateLimitError("rate_limiter_read_only", 60)
        if not isinstance(account_id, str) or not _ACCOUNT_ID_RE.fullmatch(account_id):
            raise FleetRateLimitError("rate_limiter_invalid_account", 60)
        model_key = self._normalize_gemini_model(model)
        with self._io.lock():
            now = self._rate_now()
            entries = self._load_rate_limits()
            quota = self.gemini_quota_profile(account_id, model=model_key)
            entry = entries.get(account_id)
            if entry is None:
                now_text = self._rate_text(now)
                entry = {
                    "next_allowed_at_utc": now_text,
                    "cooldown_until_utc": None,
                    "in_flight": None,
                    "consecutive_429": 0,
                    "models": {},
                }
                entries[account_id] = entry
            if entry is not None:
                retries: list[str | None] = [
                    entry.get("next_allowed_at_utc") if isinstance(entry.get("next_allowed_at_utc"), str) else None,
                    entry.get("cooldown_until_utc") if isinstance(entry.get("cooldown_until_utc"), str) else None,
                ]
                in_flight = entry.get("in_flight")
                if isinstance(in_flight, dict):
                    retries.append(in_flight.get("expires_at_utc") if isinstance(in_flight.get("expires_at_utc"), str) else None)
                if model_key is not None:
                    models = entry.get("models")
                    if isinstance(models, dict):
                        model_entry = models.get(model_key)
                        if isinstance(model_entry, dict):
                            retries.append(
                                model_entry.get("next_allowed_at_utc")
                                if isinstance(model_entry.get("next_allowed_at_utc"), str)
                                else None,
                            )
                            retries.append(
                                model_entry.get("cooldown_until_utc")
                                if isinstance(model_entry.get("cooldown_until_utc"), str)
                                else None,
                            )
                            model_in_flight = model_entry.get("in_flight")
                            if isinstance(model_in_flight, dict):
                                retries.append(
                                    model_in_flight.get("expires_at_utc")
                                    if isinstance(model_in_flight.get("expires_at_utc"), str)
                                    else None
                                )
                retry_after = self._retry_after(now, *retries)
                if retry_after:
                    raise FleetRateLimitError("gemini_local_rate_limit", retry_after)
            reservation_id = uuid.uuid4().hex
            expires = now + timedelta(seconds=GEMINI_REQUEST_LEASE_SECONDS)
            previous_cooldown = entry.get("cooldown_until_utc")
            next_allowed = self._rate_text(now + timedelta(seconds=int(quota["local_request_interval_seconds"])))
            reservation_text = self._rate_text(expires)
            entry["next_allowed_at_utc"] = next_allowed
            entry["cooldown_until_utc"] = previous_cooldown if isinstance(previous_cooldown, str) else None
            entry["in_flight"] = {"reservation_id": reservation_id, "expires_at_utc": reservation_text}
            if model_key is not None:
                models = entry["models"]
                if not isinstance(models, dict):
                    raise ValueError("invalid_gemini_rate_limits")
                model_entry = models.get(model_key)
                if not isinstance(model_entry, dict):
                    model_entry = {
                        "next_allowed_at_utc": next_allowed,
                        "cooldown_until_utc": None,
                        "in_flight": None,
                        "consecutive_429": 0,
                    }
                model_entry["next_allowed_at_utc"] = next_allowed
                model_entry["in_flight"] = {"reservation_id": reservation_id, "expires_at_utc": reservation_text}
                models[model_key] = model_entry
            self._write_rate_limits(entries)
        return GeminiRequestReservation(account_id, model_key, reservation_id, self._rate_text(expires))

    def gemini_rate_status(self, account_id: str, *, model: str | None = None) -> dict[str, object]:
        """Return the local admission state without reserving a request."""

        now = self._rate_now()
        entry = self._load_rate_limits().get(account_id)
        model_key = self._normalize_gemini_model(model)
        if entry is None:
            return {
                "allowed": True,
                "reason": "ready",
                "retry_after_seconds": 0,
                **self.gemini_quota_profile(account_id, model=model_key),
            }
        rates: list[str | None] = [
            entry.get("next_allowed_at_utc") if isinstance(entry.get("next_allowed_at_utc"), str) else None,
            entry.get("cooldown_until_utc") if isinstance(entry.get("cooldown_until_utc"), str) else None,
        ]
        in_flight = entry.get("in_flight")
        if isinstance(in_flight, dict):
            rates.append(
                in_flight.get("expires_at_utc") if isinstance(in_flight.get("expires_at_utc"), str) else None
            )
        if model_key is not None:
            models = entry.get("models")
            if isinstance(models, dict):
                model_entry = models.get(model_key)
                if isinstance(model_entry, dict):
                    rates.extend([
                        model_entry.get("next_allowed_at_utc")
                        if isinstance(model_entry.get("next_allowed_at_utc"), str)
                        else None,
                        model_entry.get("cooldown_until_utc")
                        if isinstance(model_entry.get("cooldown_until_utc"), str)
                        else None,
                    ])
                    model_in_flight = model_entry.get("in_flight")
                    if isinstance(model_in_flight, dict):
                        rates.append(
                            model_in_flight.get("expires_at_utc")
                            if isinstance(model_in_flight.get("expires_at_utc"), str)
                            else None
                        )
        retry_after = self._retry_after(now, *rates)
        defer_until = self._latest_deadline(now, *rates)
        return {
            "allowed": retry_after == 0,
            "reason": "ready" if retry_after == 0 else "gemini_local_rate_limit",
            "retry_after_seconds": retry_after,
            "defer_until": defer_until,
            **self.gemini_quota_profile(account_id, model=model_key),
        }

    @staticmethod
    def _gate_decision(
        action: str,
        code: str,
        *,
        account_id: str | None,
        model: str | None,
        defer_until: str | None = None,
        target_agent_id: str | None = None,
        openai_fallback_reason: str | None = None,
    ) -> GeminiGateDecision:
        code = map_gemini_gate_code(code)
        diagnostic = GEMINI_GATE_DIAGNOSTICS[code]
        return GeminiGateDecision(
            action,
            code,
            str(diagnostic["reason"]),
            str(diagnostic["severity"]),
            bool(diagnostic["retryable"]),
            account_id,
            model,
            defer_until,
            target_agent_id,
            openai_fallback_reason,
        )

    def _gemini_agent_gate_code(
        self,
        agent: object,
        *,
        snapshot: FleetSnapshot | FleetSnapshotV2,
        inventory: InventorySnapshot,
    ) -> tuple[str, str | None]:
        agent_id = getattr(agent, "agent_id", None)
        account_id = getattr(agent, "account_id", None)
        model = getattr(agent, "model", None)
        if not isinstance(agent_id, str) or not isinstance(account_id, str) or not isinstance(model, str):
            return "gemini_gate_unknown", None
        account_gate = self.account_gate(agent_id, snapshot=snapshot, inventory=inventory)
        if not account_gate.allowed:
            account = next((item for item in snapshot.accounts if item.account_id == account_id), None)
            reset_at = account.reset_at_utc if account is not None else None
            return map_gemini_gate_code(account_gate.reason), reset_at
        usage = self.gemini_usage_status(account_id, model=model)
        evaluation = usage.get("quota_evaluation")
        if not isinstance(evaluation, Mapping):
            return "gemini_limits_unknown", None
        observed = evaluation.get("observed")
        limits = evaluation.get("limits")
        resets = evaluation.get("resets_at_utc")
        quota_observation = evaluation.get("quota_observation")
        if isinstance(quota_observation, Mapping):
            scope = quota_observation.get("scope")
            retry_after_seconds = quota_observation.get("retry_after_seconds")
            observed_at = quota_observation.get("at_utc")
            if scope in {"model", "account", "unknown"}:
                deferred_until = None
                valid_retry_observation = False
                if (
                    isinstance(retry_after_seconds, int)
                    and not isinstance(retry_after_seconds, bool)
                    and 0 < retry_after_seconds <= _GEMINI_MAX_USAGE_QUOTA_RETRY_SECONDS
                ):
                    observed_at_utc = self._parse_time(observed_at)
                    if observed_at_utc is not None:
                        try:
                            defer_at = datetime.fromisoformat(observed_at_utc.replace("Z", "+00:00"))
                        except ValueError:
                            defer_at = None
                        else:
                            if defer_at.tzinfo is not None:
                                deferred_at = defer_at.astimezone(timezone.utc) + timedelta(seconds=retry_after_seconds)
                                now = self._rate_now()
                                if now < deferred_at:
                                    deferred_until = self._rate_text(deferred_at)
                                valid_retry_observation = True
                if scope == "model":
                    if deferred_until is not None:
                        return "gemini_model_limited", deferred_until
                    if not valid_retry_observation:
                        return "gemini_account_limited", None
                else:
                    return "gemini_account_limited", deferred_until
        rate = self.gemini_rate_status(account_id, model=model)
        if rate["allowed"] is not True:
            return "gemini_local_rate_limited", rate.get("defer_until") if isinstance(rate.get("defer_until"), str) else None
        if not isinstance(observed, Mapping) or not isinstance(limits, Mapping):
            return "gemini_limits_unknown", None
        for metric, code in (("rpm", "gemini_rpm_exhausted"), ("tpm", "gemini_tpm_exhausted"), ("rpd", "gemini_rpd_exhausted")):
            value = observed.get(metric)
            limit = limits.get(metric)
            if isinstance(limit, int) and not isinstance(limit, bool) and limit > 0:
                if isinstance(value, int) and not isinstance(value, bool) and value >= limit:
                    reset_at = resets.get(metric) if isinstance(resets, Mapping) else None
                    return code, reset_at if isinstance(reset_at, str) else None
            else:
                return "gemini_limits_unknown", None
        return "gemini_ready", None

    def gemini_headless_gate(self, agent_id: str) -> GeminiGateDecision:
        """Decide one Gemini headless start before secret or process access."""

        snapshot = self.load()
        inventory = build_inventory(snapshot, self._pool_root)
        agent = inventory.agents.get(agent_id)
        if agent is None or agent.provider is not Provider.GEMINI_API:
            return self._gate_decision("reject", "gemini_account_unavailable", account_id=None, model=None)
        code, defer_until = self._gemini_agent_gate_code(agent, snapshot=snapshot, inventory=inventory)
        if code in {"gemini_ready", "gemini_limits_unknown"}:
            return self._gate_decision("allow", code, account_id=agent.account_id, model=agent.model)

        ready_candidates: dict[str, object] = {}
        selection_candidates: list[SelectionCandidate] = []
        for candidate in inventory.agents.values():
            if candidate.agent_id == agent.agent_id or candidate.provider is not Provider.GEMINI_API or not candidate.enabled:
                continue
            candidate_code, _candidate_reset = self._gemini_agent_gate_code(
                candidate, snapshot=snapshot, inventory=inventory,
            )
            if candidate_code not in {"gemini_ready", "gemini_limits_unknown"}:
                continue
            ready_candidates[candidate.agent_id] = candidate
            selection_candidates.append(SelectionCandidate(
                agent_id=candidate.agent_id,
                account_key=candidate.account_id or candidate.agent_id,
                model_id=candidate.model,
                task_kind=TaskKind.COMPLEX,
                model_role=ModelRole.PRIMARY,
                rotation_distance=0 if candidate.account_id == agent.account_id else 1,
            ))
        rotation = preview_selection(
            selection_candidates,
            policy=SelectionPolicy(sp3=True),
            now=self._rate_now(),
            ledger=FairnessLedger({}),
        )
        if rotation.selected is not None:
            candidate = ready_candidates[rotation.selected.agent_id]
            action = "rotate_model" if candidate.account_id == agent.account_id else "rotate_account"
            return self._gate_decision(
                action,
                code,
                account_id=agent.account_id,
                model=agent.model,
                target_agent_id=candidate.agent_id,
            )

        fallback_available = any(
            candidate.provider in {Provider.OPENAI_API, Provider.OPENAI_CHATGPT}
            and self.account_gate(candidate.agent_id, snapshot=snapshot, inventory=inventory).allowed
            for candidate in inventory.agents.values()
        )
        action = "defer_until" if defer_until is not None else "reject"
        return self._gate_decision(
            action,
            code,
            account_id=agent.account_id,
            model=agent.model,
            defer_until=defer_until,
            openai_fallback_reason=(
                "Gemini rotation exhausted; eligible OpenAI fallback may be selected."
                if fallback_available else None
            ),
        )

    def release_gemini_request(
        self,
        reservation: GeminiRequestReservation,
        *,
        outcome: str,
        reset_at_utc: str | None = None,
    ) -> None:
        if self._read_only:
            return
        if outcome not in {"completed", "provider_error", "rate_limited"}:
            raise ValueError("invalid_gemini_rate_outcome")
        with self._io.lock():
            now = self._rate_now()
            entries = self._load_rate_limits()
            entry = entries.get(reservation.account_id)
            if not isinstance(entry, dict):
                return
            account_in_flight = entry.get("in_flight")
            if (
                not isinstance(account_in_flight, dict)
                or account_in_flight.get("reservation_id") != reservation.reservation_id
            ):
                return
            model_entry: dict[str, object] | None = None
            if reservation.model is not None:
                models = entry.get("models")
                if not isinstance(models, dict):
                    return
                candidate = models.get(reservation.model)
                if not isinstance(candidate, dict):
                    return
                model_entry = candidate
                model_in_flight = model_entry.get("in_flight")
                if (
                    not isinstance(model_in_flight, dict)
                    or model_in_flight.get("reservation_id") != reservation.reservation_id
                ):
                    return

            def release_state(state: dict[str, object], *, limited: bool) -> None:
                cooldown = state.get("cooldown_until_utc")
                consecutive = state.get("consecutive_429", 0)
                if not isinstance(consecutive, int) or isinstance(consecutive, bool):
                    consecutive = 0
                if limited:
                    consecutive = min(32, consecutive + 1)
                    cooldown_at: datetime | None = None
                    if reset_at_utc is not None:
                        try:
                            cooldown_at = datetime.fromisoformat(reset_at_utc.replace("Z", "+00:00"))
                        except ValueError:
                            cooldown_at = None
                        if cooldown_at is not None and cooldown_at.tzinfo is not None:
                            cooldown_at = cooldown_at.astimezone(timezone.utc)
                    if cooldown_at is None or cooldown_at <= now:
                        seconds = min(
                            GEMINI_MAX_429_COOLDOWN_SECONDS,
                            GEMINI_INITIAL_429_COOLDOWN_SECONDS * (2 ** min(consecutive - 1, 6)),
                        )
                        cooldown_at = now + timedelta(seconds=seconds)
                    cooldown = self._rate_text(cooldown_at)
                    state["next_allowed_at_utc"] = cooldown
                elif isinstance(cooldown, str) and self._retry_after(now, cooldown) == 0:
                    cooldown = None
                    consecutive = 0
                state["cooldown_until_utc"] = cooldown if isinstance(cooldown, str) else None
                state["consecutive_429"] = consecutive
                state["in_flight"] = None

            release_state(entry, limited=outcome == "rate_limited" and reservation.model is None)
            if reservation.model is not None and outcome == "rate_limited":
                entry["next_allowed_at_utc"] = self._rate_text(now)
            if model_entry is not None:
                release_state(model_entry, limited=outcome == "rate_limited")
            entries[reservation.account_id] = entry
            self._write_rate_limits(entries)

    def _overlay_limits(
        self,
        snapshot: FleetSnapshot | FleetSnapshotV2,
        entries: dict[str, dict[str, str | None]],
    ) -> FleetSnapshot | FleetSnapshotV2:
        now = self._io.utc_now()
        active_entries: dict[str, dict[str, str | None]] = {}
        expired_ids: set[str] = set()
        for account_id, entry in entries.items():
            reset_at = entry["reset_at_utc"]
            if reset_at is not None and isinstance(now, datetime) and now.tzinfo is not None:
                try:
                    parsed = datetime.fromisoformat(reset_at.replace("Z", "+00:00"))
                    if parsed.tzinfo is not None and parsed <= now:
                        expired_ids.add(account_id)
                        continue
                except ValueError:
                    continue
            active_entries[account_id] = entry
        accounts = tuple(
            dataclass_replace(
                account,
                limit_state=LimitState.LIMITED,
                reset_at_utc=active_entries[account.account_id]["reset_at_utc"],
                limit_reason=active_entries[account.account_id]["reason"],
            ) if account.account_id in active_entries else dataclass_replace(
                account,
                limit_state=LimitState.UNKNOWN,
                reset_at_utc=None,
                limit_reason=None,
            ) if account.account_id in expired_ids else account
            for account in snapshot.accounts
        )
        return normalize_fleet_document(
            fleet_document(dataclass_replace(snapshot, accounts=accounts))
        )

    @staticmethod
    def _check_generation(snapshot: FleetSnapshot | FleetSnapshotV2, expected_generation: int) -> None:
        if (
            isinstance(expected_generation, bool)
            or not isinstance(expected_generation, int)
            or snapshot.generation != expected_generation
        ):
            raise FleetConflictError("generation_conflict")

    def registry_snapshot(self) -> FleetSnapshot | FleetSnapshotV2:
        return self._load_registry()

    def load(self) -> FleetSnapshot | FleetSnapshotV2:
        return self._overlay_limits(self._load_registry(), self._load_limits())

    def public_snapshot(self) -> dict[str, object]:
        return public_fleet_snapshot(self.load())

    def commit_snapshot(
        self,
        snapshot: FleetSnapshot | FleetSnapshotV2,
        *,
        expected_generation: int,
    ) -> FleetSnapshot | FleetSnapshotV2:
        candidate = normalize_fleet_document(fleet_document(snapshot))
        with self._io.lock():
            current = self._load_registry()
            self._check_generation(current, expected_generation)
            if candidate.generation != current.generation + 1:
                raise FleetConflictError("generation_conflict")
            return self._write_registry(candidate)

    @staticmethod
    def _credential_binding_salt_metadata(path: Path) -> tuple[int, ...] | None:
        try:
            current = path.lstat()
        except FileNotFoundError:
            return None
        except OSError:
            raise FleetSecretError("credential_binding_unavailable") from None
        if (
            not stat.S_ISREG(current.st_mode)
            or getattr(current, "st_nlink", 1) != 1
            or stat.S_IMODE(current.st_mode) != 0o600
        ):
            raise FleetSecretError("credential_binding_unavailable")
        return (
            current.st_dev,
            current.st_ino,
            current.st_mode,
            current.st_nlink,
            current.st_size,
            current.st_mtime_ns,
            current.st_ctime_ns,
        )

    def _credential_binding_salt_locked(self, *, allow_create: bool = True) -> bytes:
        path = self._paths.secrets / ".credential-binding-salt"
        try:
            current = self._load_registry()
            has_existing_binding = isinstance(current, FleetSnapshotV2) and any(
                isinstance(account, FleetAccountV2)
                and account.provider is Provider.GEMINI_API
                and account.credential_binding_id is not None
                for account in current.accounts
            )
            before = self._credential_binding_salt_metadata(path)
            salt = self._io.read_bytes(
                path,
                _CREDENTIAL_BINDING_SALT_BYTES,
                "credential_binding_salt_read_failed",
            )
            after = self._credential_binding_salt_metadata(path)
            if salt is None:
                if before is not None or after is not None or has_existing_binding or not allow_create:
                    raise FleetSecretError("credential_binding_unavailable")
                salt = secrets.token_bytes(_CREDENTIAL_BINDING_SALT_BYTES)
                self._io.replace_bytes(path, salt, 0o600)
                created = self._credential_binding_salt_metadata(path)
                salt = self._io.read_bytes(
                    path,
                    _CREDENTIAL_BINDING_SALT_BYTES,
                    "credential_binding_salt_read_failed",
                )
                verified = self._credential_binding_salt_metadata(path)
                if created is None or verified != created:
                    raise FleetSecretError("credential_binding_unavailable")
            elif (
                before is None
                or after is None
                or before != after
            ):
                raise FleetSecretError("credential_binding_unavailable")
        except FleetSecretError:
            raise
        except Exception:
            raise FleetSecretError("credential_binding_unavailable") from None
        if salt is None or len(salt) != _CREDENTIAL_BINDING_SALT_BYTES:
            raise FleetSecretError("credential_binding_unavailable")
        return salt

    def _credential_binding_id_locked(
        self,
        secret_bytes: bytes,
        *,
        allow_create_salt: bool = True,
    ) -> str:
        if not isinstance(secret_bytes, bytes):
            raise FleetSecretError("credential_binding_unavailable")
        digest = hmac.new(
            self._credential_binding_salt_locked(allow_create=allow_create_salt),
            _CREDENTIAL_BINDING_DOMAIN + secret_bytes,
            hashlib.sha256,
        ).hexdigest()
        return f"hmac-sha256:{digest}"

    def _with_g_migration_binding_evidence(
        self,
        account_ids: tuple[str, ...],
        *,
        expected_generation: int,
        callback: Callable[[FleetSnapshot, Mapping[str, str]], _T],
    ) -> _T:
        if (
            type(account_ids) is not tuple
            or not account_ids
            or any(
                type(account_id) is not str
                or _ACCOUNT_ID_RE.fullmatch(account_id) is None
                for account_id in account_ids
            )
            or len(set(account_ids)) != len(account_ids)
            or not callable(callback)
        ):
            raise FleetSecretError("credential_binding_unknown")

        with self._io.lock():
            try:
                current = self._load_registry()
                if type(current) is not FleetSnapshot:
                    raise FleetSecretError("credential_binding_unknown")
                self._check_generation(current, expected_generation)
                accounts = {account.account_id: account for account in current.accounts}
                selected = []
                for account_id in account_ids:
                    account = accounts.get(account_id)
                    if (
                        type(account) is not FleetAccount
                        or account.provider is not Provider.GEMINI_API
                        or account.secret_state is not SecretState.CONFIGURED
                    ):
                        raise FleetSecretError("credential_binding_unknown")
                    selected.append(account)

                self._credential_binding_salt_locked(allow_create=False)
                bindings: dict[str, str] = {}
                for account in selected:
                    secret_path = self._paths.secrets / f"{account.account_id}.secret"
                    before = self._credential_binding_salt_metadata(secret_path)
                    secret_bytes = self._io.read_bytes(
                        secret_path,
                        MAX_SECRET_BYTES,
                        "credential_binding_unknown",
                    )
                    after = self._credential_binding_salt_metadata(secret_path)
                    if (
                        before is None
                        or after is None
                        or before != after
                        or type(secret_bytes) is not bytes
                        or not 1 <= len(secret_bytes) <= MAX_SECRET_BYTES
                    ):
                        raise FleetSecretError("credential_binding_unknown")
                    bindings[account.account_id] = self._credential_binding_id_locked(
                        secret_bytes,
                        allow_create_salt=False,
                    )
            except Exception:
                raise FleetSecretError("credential_binding_unknown") from None
            return callback(current, MappingProxyType(bindings))

    def set_secret(
        self,
        account_id: str,
        secret: str,
        *,
        expected_generation: int,
    ) -> dict[str, object]:
        if not isinstance(secret, str):
            raise FleetSecretError("invalid_secret")
        try:
            encoded = secret.encode("utf-8")
        except UnicodeError:
            raise FleetSecretError("invalid_secret") from None
        if not 1 <= len(encoded) <= MAX_SECRET_BYTES:
            raise FleetSecretError("invalid_secret")

        with self._io.lock():
            current = self._load_registry()
            self._check_generation(current, expected_generation)
            account = next((item for item in current.accounts if item.account_id == account_id), None)
            if account is None:
                raise FleetSecretError("invalid_account")
            secret_path = self._paths.secrets / f"{account.account_id}.secret"
            try:
                previous_secret = self._io.read_bytes(
                    secret_path,
                    MAX_SECRET_BYTES,
                    "secret_read_failed",
                )
            except Exception:
                raise FleetSecretError("secret_write_failed") from None
            try:
                self._io.replace_bytes(
                    secret_path,
                    encoded,
                    0o600,
                )
            except Exception:
                raise FleetSecretError("secret_write_failed") from None
            try:
                binding_id = (
                    self._credential_binding_id_locked(encoded)
                    if isinstance(current, FleetSnapshotV2)
                    and isinstance(account, FleetAccountV2)
                    and account.provider is Provider.GEMINI_API
                    else None
                )
                updated_account = dataclass_replace(
                    account,
                    secret_state=SecretState.CONFIGURED,
                    limit_state=LimitState.UNKNOWN,
                    reset_at_utc=None,
                    last_probe_at_utc=None,
                    limit_reason=None,
                    **({"credential_binding_id": binding_id} if binding_id is not None else {}),
                )
                updated = plan_account_upsert(
                    current,
                    updated_account,
                    expected_generation=current.generation,
                )
                stored = self._write_registry(updated)
            except Exception:
                with contextlib.suppress(Exception):
                    if previous_secret is None:
                        if self._io.remove_file is not None:
                            self._io.remove_file(secret_path)
                    else:
                        self._io.replace_bytes(secret_path, previous_secret, 0o600)
                raise
        return {"configured": True, "generation": stored.generation}

    def read_secret(
        self,
        account_id: str,
        *,
        expected_generation: int,
    ) -> str:
        """Read one configured secret for a bounded provider probe only."""

        with self._io.lock():
            current = self._load_registry()
            self._check_generation(current, expected_generation)
            account = next((item for item in current.accounts if item.account_id == account_id), None)
            if account is None:
                raise FleetSecretError("invalid_account")
            if account.secret_state is SecretState.MISSING:
                raise FleetSecretError("secret_missing")
            if account.secret_state is not SecretState.CONFIGURED:
                raise FleetSecretError("secret_unavailable")
            raw = self._io.read_bytes(
                self._paths.secrets / f"{account.account_id}.secret",
                MAX_SECRET_BYTES,
                "secret_read_failed",
            )
            if raw is None:
                raise FleetSecretError("secret_missing")
            try:
                secret = raw.decode("utf-8")
            except UnicodeDecodeError:
                raise FleetSecretError("secret_read_failed") from None
            if not 1 <= len(raw) <= MAX_SECRET_BYTES:
                raise FleetSecretError("secret_read_failed")
            return secret

    def delete_account(
        self,
        account_id: str,
        *,
        expected_generation: int,
    ) -> dict[str, object]:
        with self._io.lock():
            current = self._load_registry()
            self._check_generation(current, expected_generation)
            account = next((item for item in current.accounts if item.account_id == account_id), None)
            if account is None:
                raise FleetSecretError("invalid_account")
            if account.enabled:
                raise FleetSecretError("account_must_be_disabled")
            updated = plan_account_delete(current, account_id, expected_generation=current.generation)
            if account.secret_state is not SecretState.NOT_REQUIRED:
                if self._io.remove_file is None:
                    raise FleetSecretError("secret_cleanup_unavailable")
                try:
                    if not self._io.remove_file(self._paths.secrets / f"{account.account_id}.secret"):
                        raise FleetSecretError("secret_cleanup_failed")
                except FleetSecretError:
                    raise
                except Exception:
                    raise FleetSecretError("secret_cleanup_failed") from None
            stored = self._write_registry(updated)
            entries = self._load_limits()
            if account_id in entries:
                remaining = dict(entries)
                del remaining[account_id]
                self._write_limits(remaining)
        return {
            "deleted": True,
            "generation": stored.generation,
            "cleanup_pending": False,
        }

    def remove_secret_sidecar(
        self,
        account_id: str,
        *,
        expected_generation: int,
    ) -> bool:
        with self._io.lock():
            current = self._load_registry()
            self._check_generation(current, expected_generation)
            if not any(item.account_id == account_id for item in current.accounts):
                raise FleetSecretError("invalid_account")
            if self._io.remove_file is None:
                raise FleetSecretError("secret_cleanup_unavailable")
            try:
                return self._io.remove_file(self._paths.secrets / f"{account_id}.secret")
            except Exception:
                raise FleetSecretError("secret_cleanup_failed") from None

    def _mark_limited_locked(
        self,
        account_id: str,
        *,
        reset_at_utc: str | None,
        reason: str,
    ) -> FleetSnapshot:
        self._parse_time(reset_at_utc)
        if not isinstance(reason, str) or not _LIMIT_REASON_RE.fullmatch(reason):
            raise ValueError("invalid_fleet_limits")
        current = self._load_registry()
        if not any(item.account_id == account_id for item in current.accounts):
            raise ValueError("invalid_account")
        updated = mark_account_limit(
            current,
            account_id,
            reset_at_utc=reset_at_utc,
            reason=reason,
            expected_generation=current.generation,
        )
        entries = self._load_limits()
        updated_entries = dict(entries)
        updated_entries[account_id] = {
            "reset_at_utc": reset_at_utc,
            "reason": reason,
        }
        self._write_limits(updated_entries)
        return self._write_registry(updated)

    def mark_limited(
        self,
        account_id: str,
        *,
        reset_at_utc: str | None,
        reason: str,
    ) -> FleetSnapshot:
        with self._io.lock():
            return self._mark_limited_locked(
                account_id,
                reset_at_utc=reset_at_utc,
                reason=reason,
            )

    @staticmethod
    def _probe_status(
        snapshot: FleetSnapshot,
        *,
        ready: bool,
        reason: str,
        diagnostic_code: ProbeDiagnosticCode | None = None,
        endpoint_role: ProbeEndpointRole | None = None,
        http_class: ProbeHttpClass | None = None,
        process_phase: ProbeProcessPhase | None = None,
        process_output_shape: ProbeOutputShape | None = None,
        process_stdout_shape: ProbeStdoutShape | None = None,
        process_stdout_event_class: ProbeStdoutEventClass | None = None,
        process_stdout_error_seen: bool | None = None,
        model: str | None = None,
    ) -> dict[str, object]:
        status: dict[str, object] = {
            "probed": True,
            "generation": snapshot.generation,
            "ready": ready,
            "reason": reason,
        }
        normalized_process_phase = normalize_gemini_probe_process_phase(process_phase)
        if isinstance(process_phase, str) and normalized_process_phase:
            status["process_phase"] = process_phase
        normalized_diagnostic_code = normalize_gemini_probe_diagnostic_code(diagnostic_code)
        if isinstance(diagnostic_code, str) and normalized_diagnostic_code:
            status["diagnostic_code"] = diagnostic_code
        normalized_endpoint_role = endpoint_role if endpoint_role == "generate_content" else None
        if normalized_endpoint_role is not None:
            status["endpoint_role"] = normalized_endpoint_role
        normalized_http_class = (
            http_class
            if isinstance(http_class, str) and http_class in {"2xx", "4xx", "5xx", "transport"}
            else None
        )
        if normalized_http_class is not None:
            status["http_class"] = normalized_http_class
        normalized_process_output_shape = FleetService._normalize_probe_output_shape_for_timeout(
            normalized_diagnostic_code,
            normalized_process_phase,
            process_output_shape,
        )
        normalized_process_stdout_shape = FleetService._normalize_probe_stdout_shape_for_timeout(
            normalized_diagnostic_code,
            normalized_process_phase,
            process_stdout_shape,
        )
        normalized_process_stdout_event_class = normalize_gemini_probe_stdout_event_class(
            process_stdout_event_class,
        )
        normalized_process_stdout_error_seen = (
            process_stdout_error_seen if isinstance(process_stdout_error_seen, bool) else None
        )
        if normalized_process_output_shape is not None:
            status["process_output_shape"] = normalized_process_output_shape
        if normalized_process_stdout_shape is not None:
            status["process_stdout_shape"] = normalized_process_stdout_shape
            if (
                normalized_process_stdout_shape == "gemini_probe_stdout_jsonl_incomplete"
                and normalized_process_stdout_event_class is not None
                and normalized_process_stdout_error_seen is not None
            ):
                status["process_stdout_event_class"] = normalized_process_stdout_event_class
                status["process_stdout_error_seen"] = normalized_process_stdout_error_seen
        if isinstance(model, str) and model:
            status["model"] = model
        return status

    @staticmethod
    def _normalize_probe_output_shape_for_timeout(
        diagnostic_code: ProbeDiagnosticCode | None,
        process_phase: ProbeProcessPhase | None,
        process_output_shape: ProbeOutputShape | None,
    ) -> ProbeOutputShape | None:
        normalized_diagnostic_code = normalize_gemini_probe_diagnostic_code(diagnostic_code)
        normalized_process_phase = normalize_gemini_probe_process_phase(process_phase)
        normalized_process_output_shape = normalize_gemini_probe_output_shape(process_output_shape)
        timeout_phases = frozenset({
            "gemini_probe_timeout_no_output",
            "gemini_probe_timeout_structured_no_terminal",
            "gemini_probe_timeout_output_unclassified",
        })
        if (
            normalized_diagnostic_code != "gemini_probe_process_timeout"
            or normalized_process_phase not in timeout_phases
            or normalized_process_output_shape is None
        ):
            return None
        return normalized_process_output_shape

    @staticmethod
    def _normalize_probe_stdout_shape_for_timeout(
        diagnostic_code: ProbeDiagnosticCode | None,
        process_phase: ProbeProcessPhase | None,
        process_stdout_shape: ProbeStdoutShape | None,
    ) -> ProbeStdoutShape | None:
        normalized_diagnostic_code = normalize_gemini_probe_diagnostic_code(diagnostic_code)
        normalized_process_phase = normalize_gemini_probe_process_phase(process_phase)
        normalized_process_stdout_shape = normalize_gemini_probe_stdout_shape(process_stdout_shape)
        timeout_phases = frozenset({
            "gemini_probe_timeout_no_output",
            "gemini_probe_timeout_structured_no_terminal",
            "gemini_probe_timeout_output_unclassified",
        })
        if (
            normalized_diagnostic_code != "gemini_probe_process_timeout"
            or normalized_process_phase not in timeout_phases
            or normalized_process_stdout_shape is None
        ):
            return None
        return normalized_process_stdout_shape


    @staticmethod
    def _updated_probe_account(
        account: FleetAccount,
        *,
        now: str,
        reason: str,
    ) -> FleetAccount:
        if reason == "ready":
            return dataclass_replace(
                account,
                limit_state=LimitState.READY,
                reset_at_utc=None,
                last_probe_at_utc=now,
                limit_reason=None,
            )
        if reason == "auth_invalid":
            return dataclass_replace(
                account,
                secret_state=SecretState.INVALID,
                limit_state=LimitState.UNKNOWN,
                reset_at_utc=None,
                last_probe_at_utc=None,
                limit_reason=None,
            )
        if reason == "secret_missing":
            return dataclass_replace(
                account,
                secret_state=SecretState.MISSING,
                limit_state=LimitState.UNKNOWN,
                reset_at_utc=None,
                last_probe_at_utc=None,
                limit_reason=None,
            )
        if reason in {"auth_or_billing_denied", "provider_unavailable", "model_unavailable", "runner_failed"}:
            return dataclass_replace(
                account,
                secret_state=SecretState.CONFIGURED,
                limit_state=LimitState.UNKNOWN,
                reset_at_utc=None,
                last_probe_at_utc=None,
                limit_reason=reason,
            )
        return dataclass_replace(
            account,
            limit_state=LimitState.READY,
            reset_at_utc=None,
            last_probe_at_utc=now,
            limit_reason=reason,
        )

    def _utc_text(self) -> str:
        now = self._io.utc_now()
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise ValueError("invalid_utc_clock")
        return now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    def probe_account(
        self,
        account_id: str,
        probe: Callable[[FleetAccount], ProbeResult],
        *,
        model: str | None = None,
        expected_generation: int,
    ) -> dict[str, object]:
        with self._io.lock():
            current = self._load_registry()
            self._check_generation(current, expected_generation)
            account = next((item for item in current.accounts if item.account_id == account_id), None)
            if account is None:
                raise ValueError("invalid_account")
            probed_generation = current.generation

        reservation = None
        if account.provider.value == "gemini_api":
            reservation = self.reserve_gemini_request(
                account.account_id,
                model=model,
            )
        result: ProbeResult | None = None
        try:
            result = probe(account)
        except Exception:
            result = None
        finally:
            if reservation is not None:
                model_limited = False
                valid_model_limit = False
                if (
                    isinstance(result, ProbeResult)
                    and result.error is not None
                    and result.error.kind == "account_limited"
                    and result.error.quota_observation is not None
                    and isinstance(result.model, str)
                    and result.error.quota_observation.scope == "model"
                    and result.error.quota_observation.retry_after_seconds is not None
                    and isinstance(result.error.quota_observation.retry_after_seconds, int)
                    and not isinstance(result.error.quota_observation.retry_after_seconds, bool)
                    and 0 < result.error.quota_observation.retry_after_seconds <= _GEMINI_MAX_USAGE_QUOTA_RETRY_SECONDS
                ):
                    valid_model_limit = True
                if (
                    isinstance(result, ProbeResult)
                    and result.error is not None
                    and result.error.kind == "account_limited"
                    and result.error.quota_observation is not None
                    and isinstance(result.model, str)
                ):
                    model_limited = valid_model_limit
                    self.record_gemini_usage(
                        account.account_id,
                        model=result.model,
                        status="failed",
                        gate_action="defer_until",
                        gate_code="gemini_model_limited" if model_limited else "gemini_account_limited",
                        next_reset_at_utc=result.error.reset_at_utc,
                        quota_observation=result.error.quota_observation,
                    )
                rate_limited = (
                    isinstance(result, ProbeResult)
                    and result.error is not None
                    and result.error.kind == "account_limited"
                )
                self.release_gemini_request(
                    reservation,
                    outcome=(
                        "rate_limited" if rate_limited and not model_limited
                        else "completed" if isinstance(result, ProbeResult) and result.ok
                        else "provider_error"
                    ),
                    reset_at_utc=(
                        result.error.reset_at_utc
                        if rate_limited and not model_limited and result is not None and result.error is not None
                        else None
                    ),
                )

        with self._io.lock():
            latest = self._load_registry()
            self._check_generation(latest, probed_generation)
            latest_account = next(
                (item for item in latest.accounts if item.account_id == account_id),
                None,
            )
            if latest_account is None:
                raise FleetConflictError("generation_conflict")
            diagnostic_code: ProbeDiagnosticCode | None = None
            if (
                isinstance(result, ProbeResult)
                and result.provider is latest_account.provider
                and result.ok
                and result.error is None
            ):
                reason = "ready"
            elif (
                isinstance(result, ProbeResult)
                and result.provider is latest_account.provider
                and not result.ok
                and result.error is not None
            ):
                reason = {
                    "account_limited": "limit_active",
                    "auth_invalid": "auth_invalid",
                    "auth_or_billing_denied": "auth_or_billing_denied",
                    "secret_missing": "secret_missing",
                    "provider_unavailable": "provider_unavailable",
                    "model_unavailable": "model_unavailable",
                    "runner_failed": "runner_failed",
                }.get(result.error.kind, "provider_unavailable")
                if (
                    result.error.kind == "account_limited"
                    and result.error.quota_observation is not None
                    and result.error.quota_observation.scope == "model"
                    and result.error.quota_observation.retry_after_seconds is not None
                    and isinstance(result.error.quota_observation.retry_after_seconds, int)
                    and not isinstance(result.error.quota_observation.retry_after_seconds, bool)
                    and 0 < result.error.quota_observation.retry_after_seconds <= _GEMINI_MAX_USAGE_QUOTA_RETRY_SECONDS
                ):
                    reason = "ready"

                diagnostic_code = (
                    result.error.diagnostic_code
                    if (
                        isinstance(result, ProbeResult)
                        and reason in {"provider_unavailable", "runner_failed"}
                        and result.error is not None
                    ) else None
                )
            else:
                reason = "provider_unavailable"
            process_phase: ProbeProcessPhase | None = (
                result.process_phase
                if isinstance(result, ProbeResult)
                else None
            )
            process_output_shape: ProbeOutputShape | None = (
                result.process_output_shape
                if isinstance(result, ProbeResult)
                else None
            )
            process_stdout_shape: ProbeStdoutShape | None = (
                result.process_stdout_shape
                if isinstance(result, ProbeResult)
                else None
            )
            process_stdout_event_class = (
                result.process_stdout_event_class
                if isinstance(result, ProbeResult)
                else None
            )
            process_stdout_error_seen = (
                result.process_stdout_error_seen
                if isinstance(result, ProbeResult)
                else None
            )
            endpoint_role: ProbeEndpointRole | None = (
                result.endpoint_role
                if isinstance(result, ProbeResult)
                else None
            )
            http_class: ProbeHttpClass | None = (
                result.http_class
                if isinstance(result, ProbeResult)
                else None
            )

            if reason == "limit_active":
                if isinstance(diagnostic_code, str):
                    diagnostic_code = None
                if (
                    isinstance(result, ProbeResult)
                    and result.error is not None
                ):
                    reset_at_utc = result.error.reset_at_utc
                else:
                    reset_at_utc = None
                if isinstance(reset_at_utc, str):
                    try:
                        parsed = datetime.fromisoformat(reset_at_utc.replace("Z", "+00:00"))
                    except ValueError:
                        parsed = None
                    else:
                        if parsed.tzinfo is None:
                            parsed = None
                else:
                    parsed = None
                if parsed is None or parsed <= self._rate_now():
                    try:
                        rate_status = self.gemini_rate_status(
                            account.account_id,
                            model=result.model if isinstance(result, ProbeResult) else None,
                        )
                    except Exception:
                        rate_status = {}
                    defer_until = rate_status.get("defer_until") if isinstance(rate_status, Mapping) else None
                    if isinstance(defer_until, str):
                        try:
                            parsed = datetime.fromisoformat(defer_until.replace("Z", "+00:00"))
                        except ValueError:
                            parsed = None
                        else:
                            if parsed.tzinfo is not None and parsed > self._rate_now():
                                reset_at_utc = self._rate_text(parsed.astimezone(timezone.utc))
                            else:
                                reset_at_utc = None
                    else:
                        reset_at_utc = None
                stored = self._mark_limited_locked(
                    account_id,
                    reset_at_utc=reset_at_utc,
                    reason="provider_429",
                )
                return self._probe_status(
                    stored,
                    ready=False,
                    reason=reason,
                    diagnostic_code=diagnostic_code,
                    endpoint_role=endpoint_role,
                    http_class=http_class,
                    process_phase=process_phase,
                    process_output_shape=process_output_shape,
                    process_stdout_shape=process_stdout_shape,
                    process_stdout_event_class=process_stdout_event_class,
                    process_stdout_error_seen=process_stdout_error_seen,
                    model=result.model if isinstance(result, ProbeResult) else None,
                )

            updated_account = self._updated_probe_account(
                latest_account,
                now=self._utc_text(),
                reason=reason,
            )
            updated = plan_account_upsert(
                latest,
                updated_account,
                expected_generation=latest.generation,
            )
            stored = self._write_registry(updated)
            if reason == "ready":
                entries = self._load_limits()
                if account_id in entries:
                    remaining = dict(entries)
                    del remaining[account_id]
                    self._write_limits(remaining)
            return self._probe_status(
                stored,
                ready=reason == "ready",
                reason=reason,
                diagnostic_code=diagnostic_code,
                endpoint_role=endpoint_role,
                http_class=http_class,
                process_phase=process_phase,
                process_output_shape=process_output_shape,
                process_stdout_shape=process_stdout_shape,
                process_stdout_event_class=process_stdout_event_class,
                process_stdout_error_seen=process_stdout_error_seen,
                model=result.model if isinstance(result, ProbeResult) else None,
            )

    def account_gate(
        self,
        agent_id: str,
        *,
        snapshot: FleetSnapshot | None = None,
        inventory: InventorySnapshot | None = None,
    ) -> AccountGateDecision:
        snapshot = snapshot or self.load()
        inventory = inventory or build_inventory(snapshot, self._pool_root)
        agent = inventory.agents.get(agent_id)
        if agent is None:
            return AccountGateDecision(False, "account_disabled", None, snapshot.generation)
        series = next(
            (item for item in snapshot.series if item.prefix == agent.series_prefix),
            None,
        )
        if series is None or not series.enabled:
            return AccountGateDecision(False, "account_disabled", None, snapshot.generation)
        return self._account_decision(
            snapshot,
            account_id=agent.account_id,
            provider=agent.provider,
        )

    def series_gate(
        self,
        series: FleetSeries,
        *,
        snapshot: FleetSnapshot | None = None,
    ) -> AccountGateDecision:
        snapshot = snapshot or self.load()
        if not series.enabled:
            return AccountGateDecision(
                False,
                "series_disabled",
                series.account_id,
                snapshot.generation,
            )
        return self._account_decision(
            snapshot,
            account_id=series.account_id,
            provider=series.provider,
        )

    def _account_decision(
        self,
        snapshot: FleetSnapshot | FleetSnapshotV2,
        *,
        account_id: str | None,
        provider: object,
    ) -> AccountGateDecision:
        if account_id is None:
            return AccountGateDecision(True, "ready", None, snapshot.generation)
        account = next(
            (item for item in snapshot.accounts if item.account_id == account_id),
            None,
        )
        if account is not None and account.provider is not provider:
            reason = "account_provider_mismatch"
        elif account is None or not account.enabled or account.limit_state is LimitState.DISABLED:
            reason = "account_disabled"
        elif (
            provider is Provider.GEMINI_API
            and isinstance(account, FleetAccountV2)
            and account.secret_state is SecretState.CONFIGURED
            and account.credential_binding_id is None
        ):
            reason = "credential_binding_unknown"
        elif account.secret_state is SecretState.MISSING:
            reason = "secret_missing"
        elif account.secret_state is SecretState.INVALID:
            reason = "auth_invalid"
        elif account.limit_reason == "auth_or_billing_denied":
            reason = "auth_or_billing_denied"
        elif account.limit_reason == "provider_unavailable":
            reason = "provider_unavailable"
        elif account.limit_reason == "model_unavailable":
            reason = "model_unavailable"
        elif account.limit_reason == "runner_failed":
            reason = "runner_failed"
        elif provider is Provider.OPENAI_CHATGPT:
            # Native Codex sessions are authenticated by each home’s
            # auth.json.  They have no provider quota probe and must not be
            # made stale merely because a Gemini-style probe timestamp is
            # absent.
            reason = "ready"
        elif account.limit_state is LimitState.LIMITED:
            reason = "limit_active"
        elif account.limit_state in {LimitState.UNKNOWN, LimitState.PROBING}:
            reason = "limit_unknown"
        elif account.limit_reason == "provider_unavailable":
            reason = "provider_unavailable"
        elif account.limit_reason == "model_unavailable":
            reason = "model_unavailable"
        elif not self._probe_is_fresh(account.last_probe_at_utc):
            reason = "probe_stale"
        else:
            reason = "ready"
        return AccountGateDecision(reason == "ready", reason, account_id, snapshot.generation)

    def _probe_is_fresh(self, value: str | None) -> bool:
        if value is None:
            return False
        try:
            probed_at = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return False
        now = self._io.utc_now()
        if not isinstance(now, datetime) or now.tzinfo is None or probed_at.tzinfo is None:
            return False
        age = (now.astimezone(timezone.utc) - probed_at.astimezone(timezone.utc)).total_seconds()
        return 0 <= age <= self._probe_max_age_seconds
