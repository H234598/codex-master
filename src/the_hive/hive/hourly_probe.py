"""Deterministic, fail-closed Hive hourly Runtime Image probe (record v3)."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
import contextlib
from datetime import UTC, datetime
import fcntl
import json
import os
import re
from pathlib import Path
import stat
import sys
import tempfile
from typing import Any

from the_hive.runtime_layout import LayoutError, RuntimeLayout
from the_hive.runtime_process import (
    BOUNDED_PROCESS_CLEANUP_SECONDS,
    BoundedProcessError,
    DEFAULT_STDERR_LIMIT,
    DEFAULT_STDOUT_LIMIT,
    _PROTECTED_HOME_RUNTIME_DIRECTORY,
    run_bounded,
)
from the_hive.runtime_status import (
    RUNTIME_STATUS_MCP_TIMEOUT_SECONDS,
    runtime_status,
)
from the_hive.hive.runtime import _RUNTIME_STATES, GlobalPilotReadinessV1


DETERMINISTIC_PROBE_HOURS_UTC = (0, 3, 6, 9, 12, 15, 18, 21)
STATE_FILE_NAME = "hive-hourly-health.json"
PROBE_GATE_LOCK_NAME = ".hive-hourly-probe.lock"
MAX_PROBE_STATE_BYTES = 64 * 1024
MAX_PROBE_AGE_SECONDS = 4 * 60 * 60
_PROBE_RECORD_KEYS = frozenset(
    {
        "schema_version",
        "checked_at",
        "checks",
        "commands",
        "diagnostics",
        "alarm",
        "global_pilot_readiness",
    }
)
_GLOBAL_PILOT_READINESS_KEYS = frozenset(
    {
        "schema_version",
        "pilot",
        "generation_id",
        "freshness",
        "candidate_count",
        "reason_codes",
        "raw_output",
    }
)
_PROBE_CHECK_KEYS = frozenset({"runtime_layout", "hive_runtime", "hive_doctor"})
_PROBE_COMMAND_KEYS = frozenset({"runtime_status", "hive_status", "hive_doctor"})
_PROBE_ALARM_KEYS = frozenset({"scope", "status", "reason_codes", "owner"})
_PROBE_ALARM_OWNER_KEYS = frozenset({"principal_id", "class_id", "repo_id"})
_PROBE_DIAGNOSTIC_KEYS = _PROBE_COMMAND_KEYS
_PROBE_DIAGNOSTIC_VALUE_KEYS = frozenset({"code", "exit_code", "stderr"})
_PROBE_STDERR_KEYS = frozenset({"state", "excerpt", "redaction_applied"})
_SAFE_DIAGNOSTIC_CODES = frozenset(
    {
        "ok",
        "runtime_status_red",
        "mcp_timeout",
        "mcp_cleanup_timeout",
        "command_exit_nonzero",
        "command_json_invalid",
        "command_timeout",
        "command_cleanup_bounded",
        "command_arguments_invalid",
        "command_environment_invalid",
        "command_group_unavailable",
        "command_runtime_directory_unavailable",
        "command_spawn_helper_unavailable",
        "command_cgroup_preflight_unavailable",
        "command_manager_preflight_unavailable",
        "command_native_spawn_unavailable",
        "command_cgroup_bind_unavailable",
        "command_output_invalid",
        "command_stdout_limit",
        "command_stderr_limit",
        "command_unavailable",
        "command_failed",
        "command_stderr_warning",
        "command_stderr_redaction_unavailable",
        "runtime_lifecycle_rollback_failed",
    }
)
_SAFE_DIAGNOSTIC_STDERR = frozenset({"empty", "present", "not_returned"})
_SAFE_STDERR_EXCERPT_CHARS = 1200
_HIVE_STATUS_KEYS = frozenset(
    {
        "schema_version",
        "mode",
        "counts",
        "checks",
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
        "global_pilot_readiness",
    }
)
HIVE_DIAGNOSTIC_TIMEOUT_SECONDS = 45.0
_PROBE_STARTUP_AND_PUBLISH_SLACK_SECONDS = 5.0
# Each bounded child owns the shared cleanup allowance from runtime_process.
# The remaining slack covers only the image wrapper's Python bootstrap, layout
# validation, lock acquisition and atomic record publication; all diagnostic
# subprocess time is named separately below.
RUNTIME_IMAGE_PROBE_PHASE_TIMEOUTS = (
    ("direct_mcp", RUNTIME_STATUS_MCP_TIMEOUT_SECONDS),
    ("direct_mcp_cleanup", BOUNDED_PROCESS_CLEANUP_SECONDS),
    ("hive_status", HIVE_DIAGNOSTIC_TIMEOUT_SECONDS),
    ("hive_status_cleanup", BOUNDED_PROCESS_CLEANUP_SECONDS),
    ("hive_doctor", HIVE_DIAGNOSTIC_TIMEOUT_SECONDS),
    ("hive_doctor_cleanup", BOUNDED_PROCESS_CLEANUP_SECONDS),
    ("startup_and_publish", _PROBE_STARTUP_AND_PUBLISH_SLACK_SECONDS),
)
RUNTIME_IMAGE_PROBE_TOTAL_TIMEOUT_SECONDS = sum(
    seconds for _phase, seconds in RUNTIME_IMAGE_PROBE_PHASE_TIMEOUTS
)
_RUNTIME_IMAGE_PROBE_PHASE_LIMITS = dict(RUNTIME_IMAGE_PROBE_PHASE_TIMEOUTS)
_PROTECTED_HOME_RUNTIME_ARGUMENT = "--protected-home-runtime"


def _ready_state(value: object) -> bool:
    return value == "ready"


def _digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 71
        and value.startswith("sha256:")
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _bounded_global_pilot_readiness(value: object) -> dict[str, object]:
    if (
        not isinstance(value, Mapping)
        or frozenset(value) != _GLOBAL_PILOT_READINESS_KEYS
    ):
        return {
            "schema_version": 1,
            "pilot": "blocked",
            "generation_id": None,
            "freshness": "unknown",
            "candidate_count": 0,
            "reason_codes": ["usage_missing"],
            "raw_output": "not_returned",
        }
    generation_id = value.get("generation_id")
    reasons = value.get("reason_codes")
    if not isinstance(reasons, list):
        return {
            "schema_version": 1,
            "pilot": "blocked",
            "generation_id": None,
            "freshness": "unknown",
            "candidate_count": 0,
            "reason_codes": ["usage_invalid"],
            "raw_output": "not_returned",
        }
    try:
        return GlobalPilotReadinessV1(
            pilot=value["pilot"],
            generation_id=generation_id,
            freshness=value["freshness"],
            candidate_count=value["candidate_count"],
            reason_codes=tuple(reasons),
        ).public()
    except (TypeError, ValueError):
        return {
            "schema_version": 1,
            "pilot": "blocked",
            "generation_id": None,
            "freshness": "unknown",
            "candidate_count": 0,
            "reason_codes": ["usage_invalid"],
            "raw_output": "not_returned",
        }


def _green_hive_runtime(value: object) -> bool:
    if not isinstance(value, Mapping) or frozenset(value) != _HIVE_STATUS_KEYS:
        return False
    counts = value.get("counts")
    checks = value.get("checks")
    reasons = value.get("reason_codes")
    return (
        type(value.get("schema_version")) is int
        and value.get("schema_version") == 1
        and value.get("mode") == "enforced"
        and _digest(value.get("config_digest"))
        and _digest(value.get("catalog_digest"))
        and type(counts) is dict
        and frozenset(counts) == {"principals", "repositories"}
        and all(type(item) is int and item >= 0 for item in counts.values())
        and type(checks) is dict
        and frozenset(checks) == {"authority", "repository", "state"}
        and all(_ready_state(checks.get(key)) for key in checks)
        and all(
            _ready_state(value.get(key))
            for key in ("authority", "repository", "principal", "state", "pilot")
        )
        and type(reasons) is list
        and not reasons
        and value.get("mutation_performed") is False
        and value.get("raw_output") == "not_returned"
        and value.get("global_pilot_readiness")
        == _bounded_global_pilot_readiness(value.get("global_pilot_readiness"))
    )


def _green_runtime_status(value: object) -> bool:
    if not isinstance(value, Mapping) or value.get("ok") is not True:
        return False
    metadata = value.get("metadata")
    surface = value.get("mcp_surface")
    return (
        isinstance(metadata, Mapping)
        and metadata.get("ok") is True
        and metadata.get("reason_code") == "ok"
        and isinstance(surface, Mapping)
        and surface.get("ok") is True
        and surface.get("initialize") is True
        and surface.get("tools_list") is True
        and type(surface.get("tool_count")) is int
        and surface.get("tool_count") >= 1
        and surface.get("reason_code") == "ok"
        and value.get("raw_output") == "not_returned"
    )


def evaluate(
    runtime_status: Mapping[str, Any],
    hive: Mapping[str, Any],
    doctor: Mapping[str, Any],
) -> dict[str, Any]:
    """Reduce direct Runtime Image and Hive diagnostics to v2 booleans."""

    runtime_status = runtime_status if isinstance(runtime_status, Mapping) else {}
    hive = hive if isinstance(hive, Mapping) else {}
    doctor = doctor if isinstance(doctor, Mapping) else {}
    doctor_checks = doctor.get("checks")
    doctor_ready = isinstance(doctor_checks, Mapping) and all(
        _ready_state(doctor_checks.get(key))
        for key in ("authority", "repository", "state")
    )
    checks = {
        "runtime_layout": _green_runtime_status(runtime_status),
        "hive_runtime": _green_hive_runtime(hive),
        "hive_doctor": doctor.get("healthy") is True and doctor_ready,
    }
    return {
        "checks": checks,
        "global_pilot_readiness": _bounded_global_pilot_readiness(
            hive.get("global_pilot_readiness")
        ),
    }


def _valid_alarm_owner(value: object) -> bool:
    return (
        isinstance(value, Mapping)
        and frozenset(value) == _PROBE_ALARM_OWNER_KEYS
        and value.get("class_id") == "koenigin"
        and all(
            isinstance(value.get(key), str) and 1 <= len(value[key]) <= 128
            for key in _PROBE_ALARM_OWNER_KEYS
        )
    )


def _valid_diagnostic(value: object, *, command_ready: bool) -> bool:
    if (
        not isinstance(value, Mapping)
        or frozenset(value) != _PROBE_DIAGNOSTIC_VALUE_KEYS
    ):
        return False
    code = value.get("code")
    exit_code = value.get("exit_code")
    stderr = value.get("stderr")
    if (
        not isinstance(code, str)
        or code not in _SAFE_DIAGNOSTIC_CODES
        or (
            exit_code is not None
            and (type(exit_code) is not int or not -255 <= exit_code <= 255)
        )
        or not isinstance(stderr, Mapping)
        or frozenset(stderr) != _PROBE_STDERR_KEYS
        or stderr.get("state") not in _SAFE_DIAGNOSTIC_STDERR
        or not isinstance(stderr.get("excerpt"), str)
        or len(stderr["excerpt"]) > _SAFE_STDERR_EXCERPT_CHARS
        or type(stderr.get("redaction_applied")) is not bool
    ):
        return False
    if stderr["state"] != "present" and (
        stderr["excerpt"] or stderr["redaction_applied"]
    ):
        return False
    if stderr["state"] == "present" and not stderr["excerpt"]:
        return False
    if command_ready:
        return code == "ok" and exit_code == 0 and stderr["state"] == "empty"
    return code != "ok"


def _valid_alarm(value: object, checks: Mapping[str, object]) -> bool:
    if not isinstance(value, Mapping) or frozenset(value) != _PROBE_ALARM_KEYS:
        return False
    if value.get("scope") != "hive" or not isinstance(value.get("reason_codes"), list):
        return False
    reasons = value["reason_codes"]
    if any(not isinstance(reason, str) or not reason for reason in reasons):
        return False
    failed_checks = sorted(name for name, ready in checks.items() if ready is not True)
    owner = value.get("owner")
    if all(ready is True for ready in checks.values()):
        return (
            value.get("status") == "cleared"
            and reasons == []
            and _valid_alarm_owner(owner)
        )
    expected_reasons = failed_checks + (
        [] if owner is not None else ["alarm_owner_unavailable"]
    )
    return (
        value.get("status") == "active"
        and reasons == expected_reasons
        and (owner is None or _valid_alarm_owner(owner))
    )


# Adjacent to the existing v3 record constants.
_SERVICE_CHECK_KEYS = frozenset(
    {"runtime_surface", "configuration", "repository", "principals", "state", "usage"}
)
_PROBE_RECORD_V4_KEYS = _PROBE_RECORD_KEYS | {"service_checks", "service_alarm"}
_HIVE_DOCTOR_KEYS = (_HIVE_STATUS_KEYS - {"schema_version", "counts", "authority"}) | {"healthy"}
_RUNTIME_STATUS_KEYS = frozenset({"ok", "metadata", "mcp_surface", "raw_output"})
_RUNTIME_METADATA_KEYS = frozenset({"ok", "reason_code"})
_RUNTIME_SURFACE_KEYS = frozenset(
    {"ok", "initialize", "tools_list", "tool_count", "reason_code"}
)
_RUNTIME_SURFACE_REASONS = frozenset(
    {"ok", "metadata_invalid", "mcp_timeout", "mcp_cleanup_timeout", "mcp_unavailable", "mcp_surface_invalid"}
)
_RUNTIME_METADATA_REASONS = frozenset({"ok", "metadata_invalid"})


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON member")
        result[name] = value
    return result


def _reject_nonfinite(value: str) -> object:
    del value
    raise ValueError("nonfinite JSON number")


def _strict_json_loads(raw: str | bytes) -> object:
    return json.loads(
        raw,
        object_pairs_hook=_unique_json_object,
        parse_constant=_reject_nonfinite,
    )


def _valid_global_pilot_readiness(value: object) -> bool:
    if type(value) is not dict or frozenset(value) != _GLOBAL_PILOT_READINESS_KEYS:
        return False
    reasons = value.get("reason_codes")
    if type(reasons) is not list:
        return False
    try:
        expected = GlobalPilotReadinessV1(
            pilot=value.get("pilot"),
            generation_id=value.get("generation_id"),
            freshness=value.get("freshness"),
            candidate_count=value.get("candidate_count"),
            reason_codes=tuple(reasons),
        ).public()
    except (TypeError, ValueError):
        return False
    return value == expected


def _valid_runtime_status_shape(value: object) -> bool:
    if type(value) is not dict or frozenset(value) != _RUNTIME_STATUS_KEYS:
        return False
    metadata = value.get("metadata")
    surface = value.get("mcp_surface")
    if (
        type(value.get("ok")) is not bool
        or value.get("raw_output") != "not_returned"
        or type(metadata) is not dict
        or frozenset(metadata) != _RUNTIME_METADATA_KEYS
        or type(metadata.get("ok")) is not bool
        or type(metadata.get("reason_code")) is not str
        or metadata["reason_code"] not in _RUNTIME_METADATA_REASONS
        or type(surface) is not dict
        or frozenset(surface) != _RUNTIME_SURFACE_KEYS
        or any(type(surface.get(key)) is not bool for key in ("ok", "initialize", "tools_list"))
        or type(surface.get("tool_count")) is not int
        or surface["tool_count"] < 0
        or type(surface.get("reason_code")) is not str
        or surface["reason_code"] not in _RUNTIME_SURFACE_REASONS
        or value["ok"] is not surface["ok"]
    ):
        return False
    if metadata["ok"] is False:
        return metadata["reason_code"] == "metadata_invalid" and surface["ok"] is False
    return metadata["reason_code"] == "ok"


def _valid_reason_codes(value: object) -> bool:
    return (
        type(value) is list
        and all(
            isinstance(code, str)
            and 1 <= len(code) <= 96
            and re.fullmatch(r"[a-z][a-z0-9_-]*", code) is not None
            for code in value
        )
        and len(set(value)) == len(value)
    )


def _valid_hive_status_shape(value: object) -> bool:
    if type(value) is not dict or frozenset(value) != _HIVE_STATUS_KEYS:
        return False
    counts = value.get("counts")
    checks = value.get("checks")
    reasons = value.get("reason_codes")
    if (
        type(value.get("schema_version")) is not int
        or value["schema_version"] != 1
        or type(value.get("mode")) is not str
        or value["mode"] not in {"disabled", "shadow", "enforced"}
        or type(counts) is not dict
        or frozenset(counts) != {"principals", "repositories"}
        or any(type(item) is not int or item < 0 for item in counts.values())
        or type(checks) is not dict
        or frozenset(checks) != {"authority", "repository", "state"}
        or type(checks["authority"]) is not str
        or checks["authority"] not in {"ready", "fail_closed"}
        or any(type(checks[key]) is not str or checks[key] not in _RUNTIME_STATES for key in ("repository", "state"))
        or type(value.get("authority")) is not str
        or value["authority"] not in {"ready", "fail_closed"}
        or any(type(value.get(key)) is not str or value[key] not in _RUNTIME_STATES for key in ("repository", "principal", "state"))
        or type(value.get("pilot")) is not str
        or value["pilot"] not in {"ready", "blocked"}
        or not _valid_reason_codes(reasons)
        or any(value.get(key) is not None and not _digest(value.get(key)) for key in ("config_digest", "catalog_digest"))
        or type(value.get("mutation_performed")) is not bool
        or value.get("raw_output") != "not_returned"
        or not _valid_global_pilot_readiness(value.get("global_pilot_readiness"))
    ):
        return False
    return checks == {
        "authority": value["authority"],
        "repository": value["repository"],
        "state": value["state"],
    }


def _valid_hive_doctor_shape(value: object) -> bool:
    if type(value) is not dict or frozenset(value) != _HIVE_DOCTOR_KEYS:
        return False
    checks = value.get("checks")
    reasons = value.get("reason_codes")
    if (
        type(value.get("healthy")) is not bool
        or type(value.get("mode")) is not str
        or value["mode"] not in {"disabled", "shadow", "enforced"}
        or type(checks) is not dict
        or frozenset(checks) != {"authority", "repository", "state"}
        or type(checks["authority"]) is not str
        or checks["authority"] not in {"ready", "fail_closed"}
        or any(type(checks[key]) is not str or checks[key] not in _RUNTIME_STATES for key in ("repository", "state"))
        or any(type(value.get(key)) is not str or value[key] not in _RUNTIME_STATES for key in ("repository", "principal", "state"))
        or type(value.get("pilot")) is not str
        or value["pilot"] not in {"ready", "blocked"}
        or not _valid_reason_codes(reasons)
        or any(value.get(key) is not None and not _digest(value.get(key)) for key in ("config_digest", "catalog_digest"))
        or type(value.get("mutation_performed")) is not bool
        or value.get("raw_output") != "not_returned"
        or not _valid_global_pilot_readiness(value.get("global_pilot_readiness"))
    ):
        return False
    expected_healthy = all(
        (checks["authority"] if key == "authority" else value[key]) == "ready"
        for key in ("authority", "pilot", "state", "repository", "principal")
    )
    return (
        checks == {"authority": checks["authority"], "repository": value["repository"], "state": value["state"]}
        and value["healthy"] is expected_healthy
    )


def _valid_service_producer_shapes(
    runtime: object, hive: object, doctor: object, readiness: object
) -> bool:
    return (
        _valid_runtime_status_shape(runtime)
        and _valid_hive_status_shape(hive)
        and _valid_hive_doctor_shape(doctor)
        and hive["mode"] == doctor["mode"]
        and hive["authority"] == doctor["checks"]["authority"]
        and hive["repository"] == doctor["repository"]
        and hive["principal"] == doctor["principal"]
        and hive["state"] == doctor["state"]
        and hive["pilot"] == doctor["pilot"]
        and hive["checks"] == doctor["checks"]
        and hive["config_digest"] == doctor["config_digest"]
        and hive["catalog_digest"] == doctor["catalog_digest"]
        and hive["global_pilot_readiness"] == doctor["global_pilot_readiness"]
        and hive["global_pilot_readiness"] == readiness
        and hive["mutation_performed"] is doctor["mutation_performed"]
        and hive["reason_codes"] == doctor["reason_codes"]
    )


def _service_usage_value(readiness: object) -> bool:
    if not _valid_global_pilot_readiness(readiness):
        return False
    return (
        readiness["pilot"] == "ready"
        and readiness["freshness"] == "fresh"
        and isinstance(readiness["generation_id"], str)
        and bool(readiness["generation_id"])
        and readiness["reason_codes"] == []
    )


def _service_check_values(
    runtime: Mapping[str, Any],
    hive: Mapping[str, Any],
    doctor: Mapping[str, Any],
    readiness: object,
) -> dict[str, bool]:
    usage = _service_usage_value(readiness)
    if not _valid_service_producer_shapes(runtime, hive, doctor, readiness):
        failed = {name: False for name in sorted(_SERVICE_CHECK_KEYS)}
        failed["runtime_surface"] = _green_runtime_status(runtime)
        failed["usage"] = usage
        return failed
    counts = hive["counts"]
    checks = hive["checks"]
    doctor_checks = doctor["checks"]
    expected_authority_state = (
        hive["authority"] == "fail_closed"
        and doctor["checks"]["authority"] == "fail_closed"
        and doctor["healthy"] is False
    )
    digests_match = (
        _digest(hive["config_digest"])
        and _digest(hive["catalog_digest"])
        and hive["config_digest"] == doctor["config_digest"]
        and hive["catalog_digest"] == doctor["catalog_digest"]
    )
    return {
        "runtime_surface": _green_runtime_status(runtime),
        "configuration": (
            expected_authority_state
            and hive["mode"] == "enforced"
            and doctor["mode"] == "enforced"
            and digests_match
            and hive["reason_codes"] == []
        ),
        "repository": (
            hive["repository"] == "ready"
            and doctor["repository"] == "ready"
            and checks["repository"] == "ready"
            and doctor_checks["repository"] == "ready"
            and counts["repositories"] > 0
        ),
        "principals": (
            hive["principal"] == "ready"
            and doctor["principal"] == "ready"
            and counts["principals"] > 0
        ),
        "state": (
            hive["state"] == "ready"
            and doctor["state"] == "ready"
            and checks["state"] == "ready"
            and doctor_checks["state"] == "ready"
            and hive["mutation_performed"] is False
            and doctor["mutation_performed"] is False
        ),
        "usage": usage,
    }


def _valid_probe_record_v3(payload: object) -> bool:
    """Validate the original complete v3 record without changing its contract."""

    if not isinstance(payload, Mapping) or frozenset(payload) != _PROBE_RECORD_KEYS:
        return False
    checks = payload.get("checks")
    commands = payload.get("commands")
    diagnostics = payload.get("diagnostics")
    checked_at = payload.get("checked_at")
    if (
        payload.get("schema_version") != 3
        or not isinstance(checked_at, str)
        or not 1 <= len(checked_at) <= 40
        or not isinstance(checks, Mapping)
        or frozenset(checks) != _PROBE_CHECK_KEYS
        or any(type(value) is not bool for value in checks.values())
        or not isinstance(commands, Mapping)
        or frozenset(commands) != _PROBE_COMMAND_KEYS
        or any(type(value) is not bool for value in commands.values())
        or not isinstance(diagnostics, Mapping)
        or frozenset(diagnostics) != _PROBE_DIAGNOSTIC_KEYS
        or any(
            not _valid_diagnostic(diagnostics[key], command_ready=commands[key] is True)
            for key in _PROBE_COMMAND_KEYS
        )
        or not _valid_alarm(payload.get("alarm"), checks)
        or payload.get("global_pilot_readiness")
        != _bounded_global_pilot_readiness(payload.get("global_pilot_readiness"))
    ):
        return False
    try:
        observed = datetime.fromisoformat(checked_at.replace("Z", "+00:00"))
    except (TypeError, ValueError, OverflowError):
        return False
    return observed.tzinfo is not None and observed.utcoffset() is not None



def _valid_probe_record_v4(payload: object) -> bool:
    if not isinstance(payload, Mapping) or frozenset(payload) != _PROBE_RECORD_V4_KEYS:
        return False
    if type(payload.get("schema_version")) is not int or payload["schema_version"] != 4:
        return False
    service_checks = payload.get("service_checks")
    checks = payload.get("checks")
    readiness = payload.get("global_pilot_readiness")
    alarm = payload.get("alarm")
    service_alarm = payload.get("service_alarm")
    if (
        not isinstance(service_checks, Mapping)
        or frozenset(service_checks) != _SERVICE_CHECK_KEYS
        or any(type(value) is not bool for value in service_checks.values())
        or not _valid_alarm(service_alarm, service_checks)
    ):
        return False
    legacy = dict(payload)
    del legacy["service_checks"]
    del legacy["service_alarm"]
    legacy["schema_version"] = 3
    if not _valid_probe_record_v3(legacy):
        return False
    expected_usage = (
        readiness["pilot"] == "ready"
        and readiness["freshness"] == "fresh"
        and isinstance(readiness["generation_id"], str)
        and bool(readiness["generation_id"])
        and readiness["reason_codes"] == []
    )
    if (
        service_checks["runtime_surface"] is not checks["runtime_layout"]
        or service_checks["usage"] is not expected_usage
        or not isinstance(alarm, Mapping)
        or not isinstance(service_alarm, Mapping)
        or alarm.get("owner") != service_alarm.get("owner")
    ):
        return False
    return True


def valid_probe_record(payload: object) -> bool:
    """Validate one complete known hourly record version without raising."""
    if not isinstance(payload, Mapping):
        return False
    version = payload.get("schema_version")
    if type(version) is not int:
        return False
    try:
        if version == 3:
            return _valid_probe_record_v3(payload)
        if version == 4:
            return _valid_probe_record_v4(payload)
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
        return False
    return False


def probe_spawn_gate(
    payload: Mapping[str, Any],
    *,
    now: datetime | Callable[[], datetime] | None = None,
) -> dict[str, object]:
    """Accept only fresh, complete service-green v4; keep v3 as legacy HOLD."""
    if not isinstance(payload, Mapping) or type(payload.get("schema_version")) is not int:
        return {"allowed": False, "reason_code": "probe_ambiguous", "raw_output": "not_returned"}
    if payload.get("schema_version") == 3:
        return {"allowed": False, "reason_code": "probe_schema_legacy", "raw_output": "not_returned"}
    if payload.get("schema_version") != 4 or not _valid_probe_record_v4(payload):
        return {"allowed": False, "reason_code": "probe_red", "raw_output": "not_returned"}
    service_checks = payload["service_checks"]
    commands = payload["commands"]
    diagnostics = payload["diagnostics"]
    if (
        any(value is not True for value in service_checks.values())
        or any(value is not True for value in commands.values())
        or any(not _valid_diagnostic(diagnostics[name], command_ready=True) for name in _PROBE_COMMAND_KEYS)
        or payload["service_alarm"].get("status") != "cleared"
    ):
        return {"allowed": False, "reason_code": "probe_red", "raw_output": "not_returned"}
    checked_at = payload.get("checked_at")
    if not isinstance(checked_at, str) or not 1 <= len(checked_at) <= 40:
        return {
            "allowed": False,
            "reason_code": "probe_invalid",
            "raw_output": "not_returned",
        }
    try:
        observed = datetime.fromisoformat(checked_at.replace("Z", "+00:00"))
        reference = now() if callable(now) else (now or datetime.now(UTC))
        if (
            observed.tzinfo is None
            or observed.utcoffset() is None
            or reference.tzinfo is None
            or reference.utcoffset() is None
        ):
            raise ValueError
        age = (reference.astimezone(UTC) - observed.astimezone(UTC)).total_seconds()
    except (TypeError, ValueError, OverflowError):
        return {
            "allowed": False,
            "reason_code": "probe_invalid",
            "raw_output": "not_returned",
        }
    if age < 0 or age > MAX_PROBE_AGE_SECONDS:
        return {
            "allowed": False,
            "reason_code": "probe_stale",
            "raw_output": "not_returned",
        }
    return {"allowed": True, "reason_code": "probe_ready", "raw_output": "not_returned"}


def _read_private_probe_state(path: Path) -> Mapping[str, Any]:
    if not isinstance(path, Path) or not path.is_absolute() or path.is_symlink():
        raise ValueError("probe_state_invalid")
    try:
        parent = path.parent
        parent_stat = parent.lstat()
        path_stat = path.lstat()
        if (
            not stat.S_ISDIR(parent_stat.st_mode)
            or parent_stat.st_uid != os.geteuid()
            or stat.S_IMODE(parent_stat.st_mode) != 0o700
            or stat.S_ISLNK(path_stat.st_mode)
            or not stat.S_ISREG(path_stat.st_mode)
            or path_stat.st_nlink != 1
            or path_stat.st_uid != os.geteuid()
            or stat.S_IMODE(path_stat.st_mode) != 0o600
            or path_stat.st_size > MAX_PROBE_STATE_BYTES
        ):
            raise ValueError("probe_state_invalid")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError as exc:
        raise FileNotFoundError from exc
    except OSError as exc:
        raise ValueError("probe_state_unavailable") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev != path_stat.st_dev
            or opened.st_ino != path_stat.st_ino
            or opened.st_nlink != 1
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or not stat.S_ISREG(opened.st_mode)
        ):
            raise ValueError("probe_state_invalid")
        raw = os.read(descriptor, MAX_PROBE_STATE_BYTES + 1)
    except OSError as exc:
        raise ValueError("probe_state_unavailable") from exc
    finally:
        os.close(descriptor)
    if len(raw) > MAX_PROBE_STATE_BYTES:
        raise ValueError("probe_state_invalid")
    try:
        payload = _strict_json_loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ValueError("probe_state_invalid") from exc
    if not isinstance(payload, Mapping):
        raise ValueError("probe_state_invalid")
    return payload


def _probe_state_root() -> Path:
    return Path.home() / ".local" / "state" / "codex-master-mcp"


def read_probe_gate(
    *,
    state_file: Path | None = None,
    now: datetime | Callable[[], datetime] | None = None,
) -> dict[str, object]:
    """Read the private versioned record without creating or changing state."""

    if state_file is None:
        state_file = _probe_state_root() / STATE_FILE_NAME
    try:
        payload = _read_private_probe_state(state_file)
    except FileNotFoundError:
        return {
            "allowed": False,
            "reason_code": "probe_missing",
            "raw_output": "not_returned",
        }
    except (OSError, ValueError):
        return {
            "allowed": False,
            "reason_code": "probe_invalid",
            "raw_output": "not_returned",
        }
    return probe_spawn_gate(payload, now=now)


def _probe_gate_lock_path(state_file: Path) -> Path:
    if not isinstance(state_file, Path) or not state_file.is_absolute():
        raise ValueError("probe_gate_lock_invalid")
    return state_file.parent / PROBE_GATE_LOCK_NAME


def _open_probe_gate_lock(state_file: Path, *, create: bool) -> int:
    lock_path = _probe_gate_lock_path(state_file)
    try:
        parent = lock_path.parent.lstat()
        if (
            stat.S_ISLNK(parent.st_mode)
            or not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.geteuid()
            or stat.S_IMODE(parent.st_mode) != 0o700
        ):
            raise ValueError("probe_gate_lock_invalid")
        if create:
            try:
                descriptor = os.open(
                    lock_path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
            except FileExistsError:
                descriptor = -1
            else:
                os.close(descriptor)
        item = lock_path.lstat()
        if (
            stat.S_ISLNK(item.st_mode)
            or not stat.S_ISREG(item.st_mode)
            or item.st_nlink != 1
            or item.st_uid != os.geteuid()
            or stat.S_IMODE(item.st_mode) != 0o600
        ):
            raise ValueError("probe_gate_lock_invalid")
        descriptor = os.open(lock_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise ValueError("probe_gate_lock_invalid") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != item.st_dev
            or opened.st_ino != item.st_ino
            or opened.st_nlink != 1
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
        ):
            raise ValueError("probe_gate_lock_invalid")
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


@contextlib.contextmanager
def _probe_gate_lock(state_file: Path, *, exclusive: bool, create: bool) -> object:
    descriptor = _open_probe_gate_lock(state_file, create=create)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
    except OSError as exc:
        os.close(descriptor)
        raise ValueError("probe_gate_lock_unavailable") from exc
    try:
        yield
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


@contextlib.contextmanager
def probe_capacity_lock(*, state_file: Path | None = None) -> object:
    """Hold the shared state lock across one capacity-creating sink."""

    if state_file is None:
        state_file = _probe_state_root() / STATE_FILE_NAME
    with _probe_gate_lock(state_file, exclusive=False, create=False):
        yield


@contextlib.contextmanager
def probe_capacity_guard(
    *,
    state_file: Path | None = None,
    now: datetime | Callable[[], datetime] | None = None,
) -> object:
    """Read a canonical v3 record while holding the shared publication lock."""

    capacity_lock = probe_capacity_lock(state_file=state_file)
    try:
        capacity_lock.__enter__()
    except (OSError, ValueError):
        yield {
            "allowed": False,
            "reason_code": "probe_invalid",
            "raw_output": "not_returned",
        }
        return
    try:
        yield read_probe_gate(state_file=state_file, now=now)
    finally:
        capacity_lock.__exit__(*sys.exc_info())


def _state_directory(path: Path) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ValueError("unsafe_probe_state_directory")
    current = Path(path.anchor)
    try:
        for part in path.parts[1:]:
            current /= part
            try:
                item = current.lstat()
            except FileNotFoundError:
                current.mkdir(mode=0o700)
                item = current.lstat()
            if stat.S_ISLNK(item.st_mode) or not stat.S_ISDIR(item.st_mode):
                raise ValueError("unsafe_probe_state_directory")
            if current == path and (
                item.st_uid != os.geteuid() or stat.S_IMODE(item.st_mode) != 0o700
            ):
                raise ValueError("unsafe_probe_state_directory")
    except (OSError, ValueError) as exc:
        raise ValueError("unsafe_probe_state_directory") from exc
    if path == Path(path.anchor):
        raise ValueError("unsafe_probe_state_directory")
    return path


def _atomic_write(path: Path, payload: Mapping[str, object]) -> None:
    try:
        existing = path.lstat()
    except FileNotFoundError:
        existing = None
    except OSError as exc:
        raise ValueError("probe_state_write_failed") from exc
    if existing is not None and (
        stat.S_ISLNK(existing.st_mode)
        or not stat.S_ISREG(existing.st_mode)
        or existing.st_nlink != 1
        or existing.st_uid != os.geteuid()
        or stat.S_IMODE(existing.st_mode) != 0o600
    ):
        raise ValueError("probe_state_write_failed")
    try:
        encoded = (
            json.dumps(
                dict(payload), ensure_ascii=True, sort_keys=True, separators=(",", ":")
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("probe_state_encode_failed") from exc
    if len(encoded) > MAX_PROBE_STATE_BYTES:
        raise ValueError("probe_state_oversize")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_descriptor = os.open(
            path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError as exc:
        raise ValueError("probe_state_write_failed") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _probe_alarm_owner(layout: RuntimeLayout) -> dict[str, str] | None:
    """Return the sole configured repository queen for a Hive-wide alarm.

    The Runtime Image attests the configuration bytes.  An ambiguous or absent
    queen remains explicitly unassigned instead of guessing a recipient.
    """

    try:
        value = json.loads(layout.read_attested_file("codex-hive.json").decode("utf-8"))
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError, RecursionError):
        return None
    if not isinstance(value, Mapping) or not isinstance(value.get("principals"), list):
        return None
    candidates: list[dict[str, str]] = []
    for principal in value["principals"]:
        if (
            not isinstance(principal, Mapping)
            or principal.get("class_id") != "koenigin"
        ):
            continue
        principal_id = principal.get("principal_id")
        repository_id = principal.get("repo_id")
        if (
            isinstance(principal_id, str)
            and 1 <= len(principal_id) <= 128
            and isinstance(repository_id, str)
            and 1 <= len(repository_id) <= 128
        ):
            candidates.append(
                {
                    "principal_id": principal_id,
                    "class_id": "koenigin",
                    "repo_id": repository_id,
                }
            )
    return candidates[0] if len(candidates) == 1 else None



def _shape_command_result(
    value: dict[str, Any], command_ready: bool, diagnostic: dict[str, object],
    validator: Callable[[object], bool],
) -> tuple[dict[str, Any], bool, dict[str, object]]:
    try:
        shape_valid = validator(value) if command_ready else False
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
        shape_valid = False
    if not command_ready or shape_valid:
        return value, command_ready, diagnostic
    return (value, False, {
        "code": "command_output_invalid",
        "exit_code": diagnostic.get("exit_code"),
        "stderr": diagnostic.get("stderr", _not_returned_stderr()),
    })


def _probe_alarm_for_checks(
    checks: Mapping[str, object], *, owner: dict[str, str] | None
) -> dict[str, object]:
    failed_checks = sorted(name for name, ready in checks.items() if ready is not True)
    if owner is None:
        failed_checks.append("alarm_owner_unavailable")
    return {
        "scope": "hive",
        "status": "cleared" if not failed_checks else "active",
        "reason_codes": failed_checks,
        "owner": owner,
    }

def _probe_alarm_payload(
    result: Mapping[str, object], *, owner: dict[str, str] | None
) -> dict[str, object]:
    """Embed the durable Hive-wide alarm in the spawn-gated health record."""
    checks = result.get("checks")
    if not isinstance(checks, Mapping):
        return {"scope": "hive", "status": "active", "reason_codes": ["probe_result_invalid"], "owner": owner}
    return _probe_alarm_for_checks(checks, owner=owner)


def publish_lifecycle_failure(
    *,
    layout: RuntimeLayout | None,
    state_directory: Path,
    reason_code: str,
    now: Callable[[], datetime] | None = None,
) -> dict[str, Any]:
    """Fail closed with the canonical Hive-wide alarm after lifecycle rollback loss.

    This is deliberately narrower than ``run_probe``: no wrapper or diagnostic
    subprocess is started after a transaction has already lost its rollback
    guarantee.  It publishes only a valid red v3 record through the existing
    probe lock and atomic writer.
    """

    if (
        layout is not None and not isinstance(layout, RuntimeLayout)
    ) or reason_code != "runtime_lifecycle_rollback_failed":
        raise ValueError("probe_lifecycle_failure_invalid")
    state_directory = _state_directory(state_directory)
    moment = (now or (lambda: datetime.now(UTC)))()
    if (
        not isinstance(moment, datetime)
        or moment.tzinfo is None
        or moment.utcoffset() is None
    ):
        raise ValueError("probe_clock_invalid")
    checks = {"runtime_layout": False, "hive_runtime": False, "hive_doctor": False}
    diagnostic = {
        "code": reason_code,
        "exit_code": None,
        "stderr": {"state": "not_returned", "excerpt": "", "redaction_applied": False},
    }
    result: dict[str, Any] = {
        "schema_version": 4,
        "checked_at": moment.astimezone(UTC).isoformat(),
        "checks": checks,
        "commands": {
            "runtime_status": False,
            "hive_status": False,
            "hive_doctor": False,
        },
        "diagnostics": {
            "runtime_status": diagnostic,
            "hive_status": diagnostic,
            "hive_doctor": diagnostic,
        },
        "global_pilot_readiness": _bounded_global_pilot_readiness(None),
        "service_checks": {name: False for name in sorted(_SERVICE_CHECK_KEYS)},
    }
    owner = _probe_alarm_owner(layout) if layout is not None else None
    result["alarm"] = _probe_alarm_payload(result, owner=owner)
    result["service_alarm"] = _probe_alarm_for_checks(result["service_checks"], owner=owner)
    state_file = state_directory / STATE_FILE_NAME
    with _probe_gate_lock(state_file, exclusive=True, create=True):
        _atomic_write(state_file, result)
    return result


def _emit_phase_timeout(phase: str) -> None:
    """Publish the bounded phase and its named limit without child output."""

    print(
        "runtime_image_probe_phase_timeout "
        f"phase={phase} limit_seconds={_RUNTIME_IMAGE_PROBE_PHASE_LIMITS[phase]:g}",
        file=sys.stderr,
        flush=True,
    )


def _safe_stderr(value: object) -> dict[str, object]:
    """Project bounded child stderr through the existing redaction policy."""

    if not isinstance(value, str):
        return {"state": "not_returned", "excerpt": "", "redaction_applied": False}
    if not value:
        return {"state": "empty", "excerpt": "", "redaction_applied": False}
    try:
        # The server owns the product's established ANSI stripping, secret and
        # absolute-path redaction policy. This is reached only after the probe
        # module has already been loaded from an attested Runtime Image.
        from the_hive.server import command_excerpt

        excerpt, redacted = command_excerpt(value, _SAFE_STDERR_EXCERPT_CHARS)
    except (ImportError, TypeError, ValueError):
        return {
            "state": "present",
            "excerpt": "redaction_unavailable",
            "redaction_applied": True,
        }
    if not isinstance(excerpt, str) or not excerpt:
        return {
            "state": "present",
            "excerpt": "redaction_unavailable",
            "redaction_applied": True,
        }
    return {
        "state": "present",
        "excerpt": excerpt,
        "redaction_applied": redacted is True,
    }


def _not_returned_stderr() -> dict[str, object]:
    return {"state": "not_returned", "excerpt": "", "redaction_applied": False}


def _diagnostic(code: str, exit_code: int | None, stderr: object) -> dict[str, object]:
    safe_stderr = _safe_stderr(stderr)
    if safe_stderr["excerpt"] == "redaction_unavailable":
        code = "command_stderr_redaction_unavailable"
    return {"code": code, "exit_code": exit_code, "stderr": safe_stderr}


def _run_json(
    layout: RuntimeLayout,
    command: Path,
    *arguments: str,
    phase: str,
    bound_runtime_directory: Path | None = None,
) -> tuple[dict[str, Any], bool, dict[str, object]]:
    """Run one bounded command and retain a safe, bounded failure cause."""

    try:
        completed = run_bounded(
            [os.fspath(command), *arguments],
            cwd=command.parent.parent,
            home=Path.home(),
            timeout_seconds=HIVE_DIAGNOSTIC_TIMEOUT_SECONDS,
            stdout_limit=DEFAULT_STDOUT_LIMIT,
            stderr_limit=DEFAULT_STDERR_LIMIT,
            runtime_layout=layout,
            bound_runtime_directory=bound_runtime_directory,
        )
        if completed.returncode != 0:
            return (
                {},
                False,
                _diagnostic(
                    "command_exit_nonzero", completed.returncode, completed.stderr
                ),
            )
        if completed.stderr:
            return (
                {},
                False,
                _diagnostic("command_stderr_warning", 0, completed.stderr),
            )
        try:
            value = _strict_json_loads(completed.stdout)
        except (json.JSONDecodeError, TypeError, ValueError):
            return (
                {},
                False,
                _diagnostic("command_json_invalid", 0, completed.stderr),
            )
        if isinstance(value, dict):
            return (
                value,
                True,
                _diagnostic("ok", 0, completed.stderr),
            )
        return (
            {},
            False,
            _diagnostic("command_json_invalid", 0, completed.stderr),
        )
    except BoundedProcessError as exc:
        if exc.code == "command_timeout":
            _emit_phase_timeout(phase)
        elif exc.code == "command_cleanup_bounded":
            _emit_phase_timeout(f"{phase}_cleanup")
        return (
            {},
            False,
            {
                "code": exc.code
                if exc.code in _SAFE_DIAGNOSTIC_CODES
                else "command_failed",
                "exit_code": None,
                "stderr": _not_returned_stderr(),
            },
        )
    except (TypeError, ValueError):
        return (
            {},
            False,
            {
                "code": "command_json_invalid",
                "exit_code": 0,
                "stderr": _not_returned_stderr(),
            },
        )


def _runtime_status_json(
    layout: RuntimeLayout, *, protected_home_runtime: bool = False
) -> tuple[dict[str, Any], bool, dict[str, object]]:
    """Run the one bounded MCP status check outside a bus-isolated child."""

    value = (
        runtime_status(layout=layout, protected_home_runtime=True)
        if protected_home_runtime
        else runtime_status(layout=layout)
    )
    reason_code = value.get("mcp_surface", {}).get("reason_code")
    if reason_code == "mcp_timeout":
        _emit_phase_timeout("direct_mcp")
    elif reason_code == "mcp_cleanup_timeout":
        _emit_phase_timeout("direct_mcp_cleanup")
    ready = value.get("ok") is True
    if ready:
        return (
            value,
            True,
            {
                "code": "ok",
                "exit_code": 0,
                "stderr": {"state": "empty", "excerpt": "", "redaction_applied": False},
            },
        )
    return (
        value,
        False,
        {
            "code": (
                reason_code
                if reason_code in {"mcp_timeout", "mcp_cleanup_timeout"}
                else "runtime_status_red"
            ),
            "exit_code": None,
            "stderr": _not_returned_stderr(),
        },
    )


def _current_release_binding(layout: RuntimeLayout) -> tuple[RuntimeLayout, Path, str]:
    """Return one still-Current immutable generation for productive probes."""

    root = layout.root
    generation = root.name
    release_root = root.parent.parent
    if (
        not root.is_absolute()
        or root.parent.name != "generations"
        or not generation
        or generation in {".", ".."}
        or "/" in generation
        or release_root / "generations" / generation != root
    ):
        raise ValueError("probe_runtime_release_unavailable")
    try:
        current = RuntimeLayout.from_current_release(
            release_root, generation, layout.manifest_digest
        )
    except (LayoutError, TypeError, ValueError) as exc:
        raise ValueError("probe_runtime_release_unavailable") from exc
    if (
        current.root != root
        or current.root_device != layout.root_device
        or current.root_inode != layout.root_inode
        or current.manifest_digest != layout.manifest_digest
    ):
        raise ValueError("probe_runtime_release_unavailable")
    return current, release_root, generation


def _injected_command_result(
    value: object,
) -> tuple[dict[str, Any], bool, dict[str, object]]:
    """Normalize the narrow test seam without hiding failed injected commands."""

    if (
        isinstance(value, tuple)
        and len(value) == 3
        and isinstance(value[0], dict)
        and type(value[1]) is bool
        and isinstance(value[2], dict)
    ):
        return value
    if (
        isinstance(value, tuple)
        and len(value) == 2
        and isinstance(value[0], dict)
        and type(value[1]) is bool
    ):
        return (
            value[0],
            value[1],
            (
                {
                    "code": "ok",
                    "exit_code": 0,
                    "stderr": {
                        "state": "empty",
                        "excerpt": "",
                        "redaction_applied": False,
                    },
                }
                if value[1]
                else {
                    "code": "command_failed",
                    "exit_code": None,
                    "stderr": _not_returned_stderr(),
                }
            ),
        )
    return (
        {},
        False,
        {"code": "command_failed", "exit_code": None, "stderr": _not_returned_stderr()},
    )


def run_probe(
    *,
    layout: RuntimeLayout | None = None,
    state_directory: Path | None = None,
    now: Callable[[], datetime] | None = None,
    runner: Callable[..., object] | None = None,
    protected_home_runtime: bool = False,
) -> dict[str, Any]:
    """Run direct v3 checks and atomically publish exactly one v3 record."""

    try:
        active_layout = (
            RuntimeLayout.from_module_path(Path(__file__)) if layout is None else layout
        )
    except LayoutError as exc:
        raise ValueError("probe_runtime_layout_unavailable") from exc
    if not isinstance(active_layout, RuntimeLayout):
        raise ValueError("probe_runtime_layout_unavailable")
    if type(protected_home_runtime) is not bool:
        raise ValueError("probe_runtime_layout_unavailable")
    state_directory = _state_directory(state_directory or _probe_state_root())
    if runner is not None:
        runtime, runtime_command, runtime_diagnostic = (
            _runtime_status_json(active_layout, protected_home_runtime=True)
            if protected_home_runtime
            else _runtime_status_json(active_layout)
        )
        hive, hive_command, hive_diagnostic = _injected_command_result(
            runner(active_layout.mcp_entrypoint, "hive", "status")
        )
        doctor, doctor_command, doctor_diagnostic = _injected_command_result(
            runner(active_layout.mcp_entrypoint, "hive", "doctor")
        )
    else:
        current_layout, release_root, generation = _current_release_binding(
            active_layout
        )
        runtime, runtime_command, runtime_diagnostic = (
            _runtime_status_json(current_layout, protected_home_runtime=True)
            if protected_home_runtime
            else _runtime_status_json(current_layout)
        )
        binding = (str(release_root), generation, current_layout.manifest_digest)
        hive, hive_command, hive_diagnostic = _injected_command_result(
            (
                _run_json(
                    current_layout,
                    current_layout.mcp_entrypoint,
                    *binding,
                    "hive",
                    "status",
                    phase="hive_status",
                    bound_runtime_directory=_PROTECTED_HOME_RUNTIME_DIRECTORY,
                )
                if protected_home_runtime
                else _run_json(
                    current_layout,
                    current_layout.mcp_entrypoint,
                    *binding,
                    "hive",
                    "status",
                    phase="hive_status",
                )
            )
        )
        doctor, doctor_command, doctor_diagnostic = _injected_command_result(
            (
                _run_json(
                    current_layout,
                    current_layout.mcp_entrypoint,
                    *binding,
                    "hive",
                    "doctor",
                    phase="hive_doctor",
                    bound_runtime_directory=_PROTECTED_HOME_RUNTIME_DIRECTORY,
                )
                if protected_home_runtime
                else _run_json(
                    current_layout,
                    current_layout.mcp_entrypoint,
                    *binding,
                    "hive",
                    "doctor",
                    phase="hive_doctor",
                )
            )
        )
    runtime, runtime_command, runtime_diagnostic = _shape_command_result(runtime, runtime_command, runtime_diagnostic, _valid_runtime_status_shape)
    hive, hive_command, hive_diagnostic = _shape_command_result(hive, hive_command, hive_diagnostic, _valid_hive_status_shape)
    doctor, doctor_command, doctor_diagnostic = _shape_command_result(doctor, doctor_command, doctor_diagnostic, _valid_hive_doctor_shape)
    result = evaluate(runtime, hive, doctor)
    result["service_checks"] = _service_check_values(
        runtime, hive, doctor, result["global_pilot_readiness"]
    )
    owner = _probe_alarm_owner(active_layout)
    if owner is None:
        result["checks"]["hive_runtime"] = False
    moment = (now or (lambda: datetime.now(UTC)))()
    if (
        not isinstance(moment, datetime)
        or moment.tzinfo is None
        or moment.utcoffset() is None
    ):
        raise ValueError("probe_clock_invalid")
    result.update(
        {
            "schema_version": 4,
            "checked_at": moment.astimezone(UTC).isoformat(),
            "commands": {
                "runtime_status": runtime_command,
                "hive_status": hive_command,
                "hive_doctor": doctor_command,
            },
            "diagnostics": {
                "runtime_status": runtime_diagnostic,
                "hive_status": hive_diagnostic,
                "hive_doctor": doctor_diagnostic,
            },
        }
    )
    result["alarm"] = _probe_alarm_payload(result, owner=owner)
    result["service_alarm"] = _probe_alarm_for_checks(result["service_checks"], owner=owner)
    state_file = state_directory / STATE_FILE_NAME
    with _probe_gate_lock(state_file, exclusive=True, create=True):
        _atomic_write(state_file, result)
    return result


def main(arguments: Sequence[str] | None = None) -> int:
    parsed_arguments = tuple(arguments or ())
    if parsed_arguments not in {
        (),
        ("--json",),
        (_PROTECTED_HOME_RUNTIME_ARGUMENT, "--json"),
    }:
        print(
            "hive_hourly_probe_error code=arguments_invalid expected=--json",
            file=sys.stderr,
            flush=True,
        )
        return 2
    try:
        result = (
            run_probe(protected_home_runtime=True)
            if parsed_arguments == (_PROTECTED_HOME_RUNTIME_ARGUMENT, "--json")
            else run_probe()
        )
    except ValueError as exc:
        print(f"hive_hourly_probe_error code={exc}", file=sys.stderr, flush=True)
        return 2
    checks = result.get("checks")
    if not isinstance(checks, Mapping):
        print(
            "hive_hourly_probe_error code=probe_result_invalid",
            file=sys.stderr,
            flush=True,
        )
        return 2
    print(
        json.dumps(
            {
                "checks": checks,
                "service_checks": result.get("service_checks"),
                "global_pilot_readiness": _bounded_global_pilot_readiness(
                    result.get("global_pilot_readiness")
                ),
            },
            sort_keys=True,
        )
    )
    service_checks = result.get("service_checks")
    commands = result.get("commands")
    diagnostics = result.get("diagnostics")
    service_alarm = result.get("service_alarm")
    if (
        not isinstance(service_checks, Mapping)
        or frozenset(service_checks) != _SERVICE_CHECK_KEYS
        or any(value is not True for value in service_checks.values())
        or not isinstance(commands, Mapping)
        or frozenset(commands) != _PROBE_COMMAND_KEYS
        or any(value is not True for value in commands.values())
        or not isinstance(diagnostics, Mapping)
        or any(not _valid_diagnostic(diagnostics[name], command_ready=True) for name in _PROBE_COMMAND_KEYS)
        or not isinstance(service_alarm, Mapping)
        or service_alarm.get("status") != "cleared"
    ):
        failed = sorted(name for name, ready in (service_checks.items() if isinstance(service_checks, Mapping) else ()) if ready is not True)
        print("hive_hourly_probe_red failed_service_checks=" + ",".join(failed), file=sys.stderr, flush=True)
        return 1
    return 0


__all__ = [
    "DETERMINISTIC_PROBE_HOURS_UTC",
    "HIVE_DIAGNOSTIC_TIMEOUT_SECONDS",
    "MAX_PROBE_AGE_SECONDS",
    "MAX_PROBE_STATE_BYTES",
    "PROBE_GATE_LOCK_NAME",
    "RUNTIME_IMAGE_PROBE_PHASE_TIMEOUTS",
    "RUNTIME_IMAGE_PROBE_TOTAL_TIMEOUT_SECONDS",
    "STATE_FILE_NAME",
    "evaluate",
    "main",
    "probe_capacity_guard",
    "probe_capacity_lock",
    "probe_spawn_gate",
    "publish_lifecycle_failure",
    "read_probe_gate",
    "run_probe",
    "valid_probe_record",
]


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
