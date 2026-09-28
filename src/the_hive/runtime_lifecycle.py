"""Fail-closed lifecycle transactions for the hourly-probe runtime.

``cutover`` owns the canonical runtime.  ``canary`` owns only one isolated,
disposable transient unit and private image.  ``status`` and ``verify`` only
inspect bounded local data and systemd's user-manager state.
"""

from __future__ import annotations

import argparse
import ast
import base64
from datetime import UTC, datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import posixpath
import secrets
import stat
import subprocess
import runpy
import shutil
import tempfile
import time
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, replace

from the_hive.runtime_process import BoundedProcessError, run_bounded


_NEW_SERVICE = "the-hive-hive-hourly-probe.service"
_NEW_TIMER = "the-hive-hive-hourly-probe.timer"
_LEGACY_SERVICE = "codex-master-hive-hourly-probe.service"
_LEGACY_TIMER = "codex-master-hive-hourly-probe.timer"
_PRICING_LAUNCHER = "the-hive-openai-pricing-inventory"
_PRICING_UNITS = (
    "the-hive-openai-pricing.service",
    "the-hive-openai-pricing.timer",
)
_EIGHT_UTC_TERMS = "OnCalendar=*-*-* 00,03,06,09,12,15,18,21:00:00 UTC"
_HOURLY_PROBE_RUNTIME_ROOT_BINDING = (
    "BindReadOnlyPaths=%h/.local/lib/the-hive-runtime:"
    "%h/.local/lib/the-hive-runtime:norbind"
)
_HOURLY_PROBE_MANAGED_RUNTIME_DIRECTORY = "RuntimeDirectory=the-hive-hourly-runtime"
_HOURLY_PROBE_MANAGED_RUNTIME_DIRECTORY_MODE = "RuntimeDirectoryMode=0700"
_HOURLY_PROBE_PROTECTED_HOME_RUNTIME_BINDING = (
    "BindReadOnlyPaths=%t/bus:%t/the-hive-hourly-runtime/bus:norbind"
)
_HOURLY_PROBE_PROTECTED_HOME_RUNTIME_ARGUMENT = "--protected-home-runtime"
_HOURLY_PROBE_STATE_BINDING = (
    "BindPaths=%h/.local/state/codex-master-mcp:"
    "%h/.local/state/codex-master-mcp:norbind"
)
_HOURLY_PROBE_STATE_WRITE_PATH = "ReadWritePaths=%h/.local/state/codex-master-mcp"
_MAX_UNIT_BYTES = 128 * 1024
_MAX_HEALTH_BYTES = 256 * 1024
_LOCK_NAME = ".runtime-lifecycle.lock"
_OBSERVATION_NAME = "runtime-lifecycle-probe-observation.json"
_MAX_OBSERVATION_BYTES = 4096
_PROBE_OBSERVATION_SECONDS = 120.0
_PROBE_OUTPUT_BYTES = 16 * 1024
_CANARY_UNIT_PREFIX = "the-hive-runtime-canary-"
_CANARY_RUNTIME_ROOT_NAME = "the-hive-runtime-canary"
_CANARY_LOCK_NAME = ".canary.lock"
_CANARY_RUN_PREFIX = "run-"
_CANARY_MANAGER_START_SECONDS = 15.0
_CANARY_RESULT_SECONDS = 112.0
_CANARY_CLEANUP_SECONDS = 5.0
_CANARY_HEALTH_BYTES = 64 * 1024
_CANARY_STAGE_CODES = frozenset(
    {
        "command_runtime_directory_unavailable",
        "command_spawn_helper_unavailable",
        "command_cgroup_preflight_unavailable",
        "command_manager_preflight_unavailable",
        "command_native_spawn_unavailable",
        "command_cgroup_bind_unavailable",
    }
)
_CANARY_SHOW_PROPERTIES = (
    "--property=LoadState,ActiveState,Description,Transient,Result,"
    "ExecMainStatus"
)
_CANARY_SYSTEMD_RUN_FAILURES = {
    "Failed to start transient service unit: Invalid argument\n": (
        "runtime_canary_manager_contract_invalid"
    ),
    "Failed to connect to user scope bus via local transport: "
    "Connection refused\n": "runtime_canary_manager_unavailable",
    "Failed to connect to user scope bus via local transport: "
    "No such file or directory\n": "runtime_canary_manager_unavailable",
    "Failed to start transient service unit: Access denied\n": (
        "runtime_canary_manager_rejected"
    ),
    "Failed to start transient service unit: Access denied as the requested "
    "operation requires interactive authentication. However, interactive "
    "authentication has not been enabled by the calling program.\n": (
        "runtime_canary_manager_rejected"
    ),
}
_ROLLBACK_PHASE_FILE_RESTORE = "file_restore"
_ROLLBACK_PHASE_GENERATION_DISCARD = "generation_discard"
_ROLLBACK_PHASE_DAEMON_RELOAD = "restore_daemon_reload"
_ROLLBACK_PHASE_ACTIONS = {
    _NEW_TIMER: "new_timer_action",
    _NEW_SERVICE: "new_service_action",
    _LEGACY_TIMER: "legacy_timer_action",
    _LEGACY_SERVICE: "legacy_service_action",
}
_ROLLBACK_PHASE_VERIFICATIONS = {
    _NEW_TIMER: "new_timer_verify",
    _NEW_SERVICE: "new_service_verify",
    _LEGACY_TIMER: "legacy_timer_verify",
    _LEGACY_SERVICE: "legacy_service_verify",
}
_ROLLBACK_FAILURE_PHASES = frozenset(
    (
        _ROLLBACK_PHASE_FILE_RESTORE,
        _ROLLBACK_PHASE_GENERATION_DISCARD,
        _ROLLBACK_PHASE_DAEMON_RELOAD,
        *_ROLLBACK_PHASE_ACTIONS.values(),
        *_ROLLBACK_PHASE_VERIFICATIONS.values(),
    )
)
_ROLLBACK_FAILURE_CODES = frozenset(
    (
        "file_restore_failed",
        "generation_discard_failed",
        "manager_action_failed",
        "unit_verify_failed",
        "unit_verify_mismatch",
        "telemetry_invalid",
    )
)
_CUTOVER_MUTATION_PHASES = frozenset(
    (
        "before_activation_reload",
        "legacy_service_stop",
        "legacy_timer_disable",
        "new_timer_enable",
        "new_service_start",
        "after_unit_removal_reload",
    )
)
_CUTOVER_MUTATION_STATUSES = frozenset(
    (
        "runtime_lifecycle_systemd_failed",
        "runtime_lifecycle_systemd_invalid",
        "runtime_lifecycle_systemd_unavailable",
    )
)
_CUTOVER_MUTATION_ERROR = "systemd_mutation_failed"
_CUTOVER_TELEMETRY_INVALID = "telemetry_invalid"
_PRODUCER_CONSUMER_CONTRACT = {
    "_PRODUCER_VERSION": "0.6.542",
    "_PRODUCER_SOURCE_MANIFEST_SHA256": "8da41af5293cf4816a04db5443b14c718d496756c666ea8854f8b053021f14f0",
    "_PRODUCER_RELEASE_ID": "0.6.542-8da41af5293cf481",
}

Systemctl = Callable[[tuple[str, ...]], Mapping[str, str]]
SystemdRun = Callable[[tuple[str, ...]], Mapping[str, str]]


class RuntimeLifecycleError(ValueError):
    """A stable, data-sparse lifecycle failure code."""


class _CutoverMutationError(RuntimeLifecycleError):
    """Carry one bounded manager phase through a successful rollback only."""

    def __init__(self, *, phase: str, error: RuntimeLifecycleError) -> None:
        status = str(error)
        self.status_whitelisted = status in _CUTOVER_MUTATION_STATUSES
        super().__init__(
            status
            if self.status_whitelisted
            else "runtime_lifecycle_systemd_failed"
        )
        self.phase = phase


def _error(code: str) -> RuntimeLifecycleError:
    return RuntimeLifecycleError(code)


class D320CutoverJournalError(ValueError):
    """D332's pure, fail-closed journal contract violation."""


_D320_SCHEMA = "D320CutoverJournalV1"
_D320_MAX_ENVELOPE_BYTES = 4_194_304
_D320_MAX_BLOB_BYTES = 1_048_576
_D320_MAX_AGGREGATE_BYTES = 3 * 1_048_576
_D320_MAX_U63 = (1 << 63) - 1
_D320_MAX_CONTAINER_DEPTH = 64
_D320_MAX_CONTAINER_NODES = 65_536
_D320_MAX_JSON_ENTRIES = 65_536
_D320_ENVELOPE_FIXED_BYTES = len(
    b'{"content_sha256":"' + b"0" * 64 + b'","payload":' + b"}\n"
)
_D320_SNAPSHOT_NAMES = (
    "pointer",
    "mcp_launcher",
    "user_launcher",
    "legacy_launcher",
    "service",
    "timer",
    "config_binding",
)
_D320_ARTIFACT_NAMES = (*_D320_SNAPSHOT_NAMES, "unit_status")
_D320_ABORT_BLOCK_REASONS = {
    "unreadable": "UNREADABLE_BLOCKED",
    "mixed_without_complete_inverse": "MIXED_BLOCKED",
    "noninvertible": "NONINVERTIBLE_BLOCKED",
}
_D320_STATES = (
    "ABSENT",
    "PREFLIGHTED",
    "ROOT_ABI_VERIFIED",
    "NATIVE_PREPARED_DISABLED",
    "NATIVE_TRUST_VERIFIED_DISABLED",
    "NATIVE_COMMITTED_DISABLED",
    "USER_CUTOVER_IN_PROGRESS",
    "USER_CUTOVER_VERIFIED",
    "ISOLATED_HOOK_PROBE_VERIFIED",
    "MCP_HANDSHAKE_VERIFIED",
    "LIVE_GRANTED",
    "ABORTING",
    "ROLLED_BACK",
    "BLOCKED",
)
_D320_NORMAL_STATES = (
    "ABSENT",
    "PREFLIGHTED",
    "ROOT_ABI_VERIFIED",
    "NATIVE_PREPARED_DISABLED",
    "NATIVE_TRUST_VERIFIED_DISABLED",
    "NATIVE_COMMITTED_DISABLED",
    "USER_CUTOVER_IN_PROGRESS",
    "USER_CUTOVER_VERIFIED",
    "ISOLATED_HOOK_PROBE_VERIFIED",
    "MCP_HANDSHAKE_VERIFIED",
    "LIVE_GRANTED",
)
_D320_TERMINAL_STATES = frozenset(("LIVE_GRANTED", "ROLLED_BACK", "BLOCKED"))
D324_LOCK_ORDER = (
    "D324-Journallock",
    "Lifecycle-Lock",
    "Rootexecutor-Lock",
    "Adapter-Lock",
    "Release-Publishlock",
    "Pin-Store-Lock",
)


def _d320_fail(code: str) -> None:
    raise D320CutoverJournalError(code)


@dataclass(slots=True)
class _D320JsonTraversalBudget:
    entries: int = 0
    nodes: int = 0


def _d320_visit_json_entry(budget: _D320JsonTraversalBudget) -> None:
    budget.entries += 1
    if budget.entries > _D320_MAX_JSON_ENTRIES:
        _d320_fail("d320_json_entries_invalid")


def _d320_visit_json_node(budget: _D320JsonTraversalBudget) -> None:
    budget.nodes += 1
    if budget.nodes > _D320_MAX_CONTAINER_NODES:
        _d320_fail("d320_json_nodes_invalid")


def _d320_budget_error(error: D320CutoverJournalError) -> bool:
    return str(error) in ("d320_json_entries_invalid", "d320_json_nodes_invalid")


def _d320_bytes_copy(value: object, *, code: str) -> bytes:
    if not isinstance(value, bytes):
        _d320_fail(code)
    if type(value) is bytes:
        return value
    try:
        return memoryview(value).tobytes()
    except MemoryError as exc:
        raise D320CutoverJournalError(code) from exc
    except Exception as exc:
        raise D320CutoverJournalError(code) from exc


def _d320_carrier_bytes(value: object, *, code: str) -> bytes:
    return _d320_bytes_copy(value, code=code)


def _d320_validate_envelope_payload_size(payload_bytes: object) -> bytes:
    payload_bytes = _d320_bytes_copy(
        payload_bytes, code="d320_envelope_too_large"
    )
    if (
        len(payload_bytes) + _D320_ENVELOPE_FIXED_BYTES
        > _D320_MAX_ENVELOPE_BYTES
    ):
        _d320_fail("d320_envelope_too_large")
    return payload_bytes


def _d320_int(value: object, *, minimum: int = 0, maximum: int = _D320_MAX_U63) -> int:
    if type(value) is not int:
        _d320_fail("d320_integer_required")
    if value < minimum or value > maximum:
        _d320_fail("d320_integer_out_of_bounds")
    return value


def _d320_text(
    value: object,
    *,
    minimum: int = 1,
    maximum: int = 4096,
    ascii_only: bool = False,
) -> str:
    if type(value) is not str:
        _d320_fail("d320_text_invalid")
    try:
        byte_length = len(value.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise D320CutoverJournalError("d320_text_invalid") from exc
    if not minimum <= byte_length <= maximum:
        _d320_fail("d320_text_invalid")
    if unicodedata.normalize("NFC", value) != value:
        _d320_fail("d320_text_not_nfc")
    for character in value:
        point = ord(character)
        if 0xD800 <= point <= 0xDFFF or point <= 0x1F or 0x7F <= point <= 0x9F:
            _d320_fail("d320_text_forbidden_codepoint")
        if ascii_only and point > 0x7F:
            _d320_fail("d320_text_not_ascii")
    return value


def _d320_sha256(value: object) -> str:
    text = _d320_text(value, minimum=64, maximum=64, ascii_only=True)
    if any(character not in "0123456789abcdef" for character in text):
        _d320_fail("d320_sha256_invalid")
    return text


def _d320_git_hex(value: object) -> str:
    text = _d320_text(value, minimum=40, maximum=64, ascii_only=True)
    if len(text) not in (40, 64) or any(
        character not in "0123456789abcdef" for character in text
    ):
        _d320_fail("d320_git_hex_invalid")
    return text


def _d320_object(
    value: object, keys: Sequence[str], *, code: str
) -> Mapping[str, object]:
    if (
        not isinstance(value, Mapping)
        or set(value) != set(keys)
        or len(value) != len(keys)
    ):
        _d320_fail(code)
    for key in value:
        _d320_text(key, ascii_only=True)
    return value


def _d320_json_value(
    value: object,
    *,
    semantic: bool = True,
    budget: _D320JsonTraversalBudget | None = None,
) -> None:
    """Bound every public JSON-shaped input before using its structure."""

    traversal_budget = budget or _D320JsonTraversalBudget()
    active: set[int] = set()
    stack: list[tuple[object, ...]] = [("value", value, 1)]
    try:
        while stack:
            action, *parts = stack.pop()
            if action == "leave":
                active.remove(int(parts[0]))
                continue
            if action == "mapping":
                iterator, depth = parts
                try:
                    key, child = next(iterator)
                except StopIteration:
                    continue
                _d320_visit_json_entry(traversal_budget)
                if semantic:
                    _d320_text(key, minimum=0, ascii_only=False)
                elif not isinstance(key, str):
                    _d320_fail("d320_json_type_forbidden")
                stack.append(("mapping", iterator, depth))
                stack.append(("value", child, int(depth) + 1))
                continue
            if action == "list":
                iterator, depth = parts
                try:
                    child = next(iterator)
                except StopIteration:
                    continue
                _d320_visit_json_entry(traversal_budget)
                stack.append(("list", iterator, depth))
                stack.append(("value", child, int(depth) + 1))
                continue
            item, depth = parts
            if item is None or isinstance(item, bool) or isinstance(item, int):
                continue
            if isinstance(item, float):
                if semantic:
                    _d320_fail("d320_float_forbidden")
                continue
            if isinstance(item, str):
                if semantic:
                    _d320_text(item, minimum=0)
                continue
            if not isinstance(item, (list, Mapping)):
                _d320_fail("d320_json_type_forbidden")
            if int(depth) > _D320_MAX_CONTAINER_DEPTH:
                _d320_fail("d320_json_depth_invalid")
            identifier = id(item)
            if identifier in active:
                _d320_fail("d320_json_cycle_invalid")
            _d320_visit_json_node(traversal_budget)
            active.add(identifier)
            stack.append(("leave", identifier))
            if isinstance(item, list):
                stack.append(("list", iter(item), int(depth)))
            else:
                stack.append(("mapping", iter(item.items()), int(depth)))
    except D320CutoverJournalError:
        raise
    except MemoryError as exc:
        raise D320CutoverJournalError("d320_json_input_invalid") from exc
    except Exception as exc:
        raise D320CutoverJournalError("d320_json_input_invalid") from exc


def _d320_normalize_json_value(
    value: object,
    *,
    budget: _D320JsonTraversalBudget,
) -> object:
    """Copy one untrusted JSON graph while applying its cumulative bounds."""

    active: set[int] = set()

    def normalize(item: object, depth: int) -> object:
        if item is None or isinstance(item, bool) or isinstance(item, int):
            return item
        if isinstance(item, float):
            _d320_fail("d320_float_forbidden")
        if isinstance(item, str):
            return _d320_text(item, minimum=0)
        if not isinstance(item, (list, Mapping)):
            _d320_fail("d320_json_type_forbidden")
        if depth > _D320_MAX_CONTAINER_DEPTH:
            _d320_fail("d320_json_depth_invalid")
        identifier = id(item)
        if identifier in active:
            _d320_fail("d320_json_cycle_invalid")
        _d320_visit_json_node(budget)
        active.add(identifier)
        try:
            if isinstance(item, list):
                result: list[object] = []
                iterator = iter(item)
                while True:
                    try:
                        child = next(iterator)
                    except StopIteration:
                        break
                    _d320_visit_json_entry(budget)
                    result.append(normalize(child, depth + 1))
                return result
            result = {}
            iterator = iter(item.items())
            while True:
                try:
                    key, child = next(iterator)
                except StopIteration:
                    break
                _d320_visit_json_entry(budget)
                key = _d320_text(key, minimum=0)
                if key in result:
                    _d320_fail("d320_duplicate_json_key")
                result[key] = normalize(child, depth + 1)
            return result
        finally:
            active.remove(identifier)

    try:
        return normalize(value, 1)
    except D320CutoverJournalError:
        raise
    except MemoryError as exc:
        raise D320CutoverJournalError("d320_json_input_invalid") from exc
    except Exception as exc:
        raise D320CutoverJournalError("d320_json_input_invalid") from exc


def _d320_canonical_json(
    value: object, *, budget: _D320JsonTraversalBudget | None = None
) -> bytes:
    traversal_budget = budget or _D320JsonTraversalBudget()
    normalized = _d320_normalize_json_value(value, budget=traversal_budget)
    try:
        return json.dumps(
            normalized,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8")
    except (MemoryError, RecursionError, TypeError, UnicodeError, ValueError) as exc:
        raise D320CutoverJournalError("d320_canonical_json_invalid") from exc


def _d320_syntax_json(
    value: object, *, budget: _D320JsonTraversalBudget | None = None
) -> bytes:
    _d320_json_value(value, semantic=False, budget=budget)
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8", errors="backslashreplace")
    except (MemoryError, RecursionError, TypeError, UnicodeError, ValueError) as exc:
        raise D320CutoverJournalError("d320_canonical_json_invalid") from exc


def _d320_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _d320_fail("d320_duplicate_json_key")
        result[key] = value
    return result


def _d320_parse_json(raw: object) -> object:
    raw = _d320_bytes_copy(raw, code="d320_json_invalid")
    try:
        text = raw.decode("utf-8")
        return json.loads(
            text,
            object_pairs_hook=_d320_pairs,
            parse_constant=lambda _value: _d320_fail("d320_nonfinite_forbidden"),
        )
    except (
        MemoryError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        TypeError,
        ValueError,
    ) as exc:
        raise D320CutoverJournalError("d320_json_invalid") from exc


def _d320_immutable_mapping(
    payload_bytes: object,
    validator: Callable[[object], Mapping[str, object]],
) -> dict[str, object]:
    payload_bytes = _d320_bytes_copy(
        payload_bytes, code="d320_wrapper_bytes_invalid"
    )
    if len(payload_bytes) > _D320_MAX_ENVELOPE_BYTES:
        _d320_fail("d320_wrapper_bytes_invalid")
    parsed = _d320_parse_json(payload_bytes)
    if not isinstance(parsed, dict):
        _d320_fail("d320_wrapper_mapping_invalid")
    _d320_json_value(parsed)
    validator(parsed)
    if _d320_canonical_json(parsed) != payload_bytes:
        _d320_fail("d320_wrapper_not_canonical")
    return parsed


def _d320_sequence_copy(
    value: object,
    *,
    maximum: int,
    code: str,
    budget: _D320JsonTraversalBudget | None = None,
) -> list[object]:
    traversal_budget = budget or _D320JsonTraversalBudget()
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        _d320_fail(code)
    try:
        length = len(value)
        if length > maximum:
            _d320_fail(code)
        iterator = iter(value)
        result: list[object] = []
        for index in range(length + 1):
            try:
                item = next(iterator)
            except StopIteration:
                if index != length:
                    _d320_fail(code)
                break
            _d320_visit_json_entry(traversal_budget)
            if index == length:
                _d320_fail(code)
            result.append(
                _d320_normalize_json_value(item, budget=traversal_budget)
            )
    except D320CutoverJournalError:
        raise
    except MemoryError as exc:
        raise D320CutoverJournalError(code) from exc
    except Exception as exc:
        raise D320CutoverJournalError(code) from exc
    return result


def _d320_base64(
    value: object,
    *,
    size: int,
    maximum_size: int = _D320_MAX_BLOB_BYTES,
) -> str:
    if not isinstance(value, str):
        _d320_fail("d320_base64_invalid")
    _d320_text(
        value,
        minimum=0,
        maximum=4 * ((maximum_size + 2) // 3),
        ascii_only=True,
    )
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise D320CutoverJournalError("d320_base64_invalid") from exc
    if base64.b64encode(decoded).decode("ascii") != value or len(decoded) != size:
        _d320_fail("d320_base64_noncanonical")
    return value


def _d320_validate_evidence(
    value: object, *, aggregate: list[int] | None = None
) -> Mapping[str, object]:
    evidence = _d320_object(
        value,
        ("kind", "format", "bytes_b64", "sha256", "size"),
        code="d320_evidence_fields_invalid",
    )
    _d320_text(evidence["kind"], maximum=64, ascii_only=True)
    _d320_text(evidence["format"], maximum=64, ascii_only=True)
    size = _d320_int(evidence["size"], maximum=_D320_MAX_BLOB_BYTES)
    encoded = _d320_base64(evidence["bytes_b64"], size=size)
    decoded = base64.b64decode(encoded.encode("ascii"), validate=True)
    if hashlib.sha256(decoded).hexdigest() != _d320_sha256(evidence["sha256"]):
        _d320_fail("d320_evidence_digest_invalid")
    if aggregate is not None:
        aggregate[0] += size
        if aggregate[0] > _D320_MAX_AGGREGATE_BYTES:
            _d320_fail("d320_evidence_aggregate_too_large")
    return evidence


def _d320_validate_absolute_path(value: object) -> str:
    path = _d320_text(value, maximum=4096)
    if not path.startswith("/") or "\x00" in path:
        _d320_fail("d320_snapshot_path_invalid")
    if posixpath.normpath(path) != path or any(
        part in ("", ".", "..") for part in path.split("/")[1:]
    ):
        _d320_fail("d320_snapshot_path_not_normal")
    return path


def _d320_validate_snapshot(
    value: object, *, aggregate: list[int] | None = None
) -> Mapping[str, object]:
    snapshot = _d320_object(
        value,
        (
            "name",
            "path",
            "present",
            "bytes_b64",
            "sha256",
            "dev",
            "ino",
            "uid",
            "gid",
            "mode",
            "nlink",
            "size",
        ),
        code="d320_snapshot_fields_invalid",
    )
    _d320_text(snapshot["name"], maximum=128, ascii_only=True)
    _d320_validate_absolute_path(snapshot["path"])
    if not isinstance(snapshot["present"], bool):
        _d320_fail("d320_snapshot_present_invalid")
    data_fields = (
        "bytes_b64",
        "sha256",
        "dev",
        "ino",
        "uid",
        "gid",
        "mode",
        "nlink",
        "size",
    )
    if not snapshot["present"]:
        if any(snapshot[field] is not None for field in data_fields):
            _d320_fail("d320_absent_snapshot_has_data")
        return snapshot
    if any(snapshot[field] is None for field in data_fields):
        _d320_fail("d320_present_snapshot_missing_data")
    size = _d320_int(snapshot["size"], maximum=_D320_MAX_AGGREGATE_BYTES)
    encoded = _d320_base64(
        snapshot["bytes_b64"],
        size=size,
        maximum_size=_D320_MAX_AGGREGATE_BYTES,
    )
    decoded = base64.b64decode(encoded.encode("ascii"), validate=True)
    if hashlib.sha256(decoded).hexdigest() != _d320_sha256(snapshot["sha256"]):
        _d320_fail("d320_snapshot_digest_invalid")
    _d320_int(snapshot["dev"])
    _d320_int(snapshot["ino"])
    _d320_int(snapshot["uid"])
    _d320_int(snapshot["gid"])
    _d320_int(snapshot["mode"], maximum=0o7777)
    _d320_int(snapshot["nlink"], minimum=1)
    if aggregate is not None:
        aggregate[0] += size
        if aggregate[0] > _D320_MAX_AGGREGATE_BYTES:
            _d320_fail("d320_evidence_aggregate_too_large")
    return snapshot


class EvidenceBlobV1(bytes):
    """A validated, immutable evidence payload carried by the bytes value itself."""

    __slots__ = ()

    def __new__(cls, payload_bytes: object) -> EvidenceBlobV1:
        payload_bytes = _d320_bytes_copy(
            payload_bytes, code="d320_wrapper_bytes_invalid"
        )
        _d320_immutable_mapping(payload_bytes, _d320_validate_evidence)
        return bytes.__new__(cls, payload_bytes)

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> EvidenceBlobV1:
        if cls is not EvidenceBlobV1:
            _d320_fail("d320_wrapper_factory_type_invalid")
        parsed = _d320_parse_json(_d320_canonical_json(value))
        _d320_validate_evidence(parsed)
        return EvidenceBlobV1(_d320_canonical_json(parsed))

    def to_mapping(self) -> dict[str, object]:
        return _d320_immutable_mapping(
            _d320_carrier_bytes(self, code="d320_wrapper_bytes_invalid"),
            _d320_validate_evidence,
        )


class ByteSnapshotV1(bytes):
    """A validated, immutable snapshot payload carried by the bytes value itself."""

    __slots__ = ()

    def __new__(cls, payload_bytes: object) -> ByteSnapshotV1:
        payload_bytes = _d320_bytes_copy(
            payload_bytes, code="d320_wrapper_bytes_invalid"
        )
        _d320_immutable_mapping(payload_bytes, _d320_validate_snapshot)
        return bytes.__new__(cls, payload_bytes)

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> ByteSnapshotV1:
        if cls is not ByteSnapshotV1:
            _d320_fail("d320_wrapper_factory_type_invalid")
        parsed = _d320_parse_json(_d320_canonical_json(value))
        _d320_validate_snapshot(parsed)
        return ByteSnapshotV1(_d320_canonical_json(parsed))

    @property
    def present(self) -> bool:
        return (
            _d320_immutable_mapping(
                _d320_carrier_bytes(self, code="d320_wrapper_bytes_invalid"),
                _d320_validate_snapshot,
            )["present"]
            is True
        )

    def to_mapping(self) -> dict[str, object]:
        return _d320_immutable_mapping(
            _d320_carrier_bytes(self, code="d320_wrapper_bytes_invalid"),
            _d320_validate_snapshot,
        )


def _d320_transition_allowed(before: str, after: str) -> bool:
    if before in _D320_TERMINAL_STATES:
        return False
    if before == "ABORTING":
        return after in ("ROLLED_BACK", "BLOCKED")
    normal_index = _D320_NORMAL_STATES.index(before)
    return after in (
        _D320_NORMAL_STATES[normal_index + 1]
        if normal_index + 1 < len(_D320_NORMAL_STATES)
        else "",
        "ABORTING",
        "BLOCKED",
    )


def _d320_validate_transition(value: object) -> Mapping[str, object]:
    transition = _d320_object(
        value,
        ("sequence", "from", "to", "at_unix_ms", "reason_code"),
        code="d320_transition_fields_invalid",
    )
    _d320_int(transition["sequence"])
    before = _d320_text(transition["from"], maximum=64, ascii_only=True)
    after = _d320_text(transition["to"], maximum=64, ascii_only=True)
    if before not in _D320_STATES or after not in _D320_STATES:
        _d320_fail("d320_transition_state_invalid")
    reason = _d320_text(transition["reason_code"], maximum=128, ascii_only=True)
    if not _d320_transition_allowed(before, after):
        _d320_fail("d320_transition_graph_invalid")
    if after == "BLOCKED":
        if reason not in _D320_ABORT_BLOCK_REASONS:
            _d320_fail("d320_abort_block_reason_invalid")
    _d320_int(transition["at_unix_ms"])
    return transition


class TransitionV1(bytes):
    """A validated, immutable transition carried by the bytes value itself."""

    __slots__ = ()

    def __new__(cls, payload_bytes: object) -> TransitionV1:
        payload_bytes = _d320_bytes_copy(
            payload_bytes, code="d320_wrapper_bytes_invalid"
        )
        _d320_immutable_mapping(payload_bytes, _d320_validate_transition)
        return bytes.__new__(cls, payload_bytes)

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> TransitionV1:
        if cls is not TransitionV1:
            _d320_fail("d320_wrapper_factory_type_invalid")
        parsed = _d320_parse_json(_d320_canonical_json(value))
        _d320_validate_transition(parsed)
        return TransitionV1(_d320_canonical_json(parsed))

    def to_mapping(self) -> dict[str, object]:
        return _d320_immutable_mapping(
            _d320_carrier_bytes(self, code="d320_wrapper_bytes_invalid"),
            _d320_validate_transition,
        )


def _d320_optional_evidence(
    value: object, *, aggregate: list[int] | None = None
) -> None:
    if value is not None:
        _d320_validate_evidence(value, aggregate=aggregate)


def _d320_validate_step(
    value: object,
    *,
    aggregate: list[int] | None = None,
    maximum_unix_ms: int | None = None,
) -> Mapping[str, object]:
    step = _d320_object(
        value,
        (
            "index",
            "operation",
            "status",
            "preconditions",
            "intent_unix_ms",
            "effect_started_unix_ms",
            "effect_ended_unix_ms",
            "readback",
            "file_fsync",
            "parent_fsync",
            "adapter_receipt",
            "inverse",
        ),
        code="d320_step_fields_invalid",
    )
    _d320_int(step["index"])
    _d320_text(step["operation"], maximum=128, ascii_only=True)
    status = _d320_text(step["status"], maximum=32, ascii_only=True)
    if status not in (
        "INTENT",
        "EFFECT_STARTED",
        "VERIFIED",
        "INVERSE_INTENT",
        "INVERSE_VERIFIED",
    ):
        _d320_fail("d320_step_status_invalid")
    _d320_validate_evidence(step["preconditions"], aggregate=aggregate)
    intent_value = _d320_int(step["intent_unix_ms"])
    if maximum_unix_ms is not None and intent_value > maximum_unix_ms:
        _d320_fail("d320_step_time_exceeds_updated")
    started = step["effect_started_unix_ms"]
    ended = step["effect_ended_unix_ms"]
    completed = status in ("VERIFIED", "INVERSE_INTENT", "INVERSE_VERIFIED")
    requires_started = status in (
        "EFFECT_STARTED",
        "VERIFIED",
        "INVERSE_INTENT",
        "INVERSE_VERIFIED",
    )
    if requires_started:
        started_value = _d320_int(started)
        if started_value < intent_value:
            _d320_fail("d320_step_time_invalid")
        if maximum_unix_ms is not None and started_value > maximum_unix_ms:
            _d320_fail("d320_step_time_exceeds_updated")
    elif started is not None:
        _d320_fail("d320_step_start_phase_invalid")
    if completed:
        ended_value = _d320_int(ended)
        if ended_value < started_value:
            _d320_fail("d320_step_time_invalid")
        if maximum_unix_ms is not None and ended_value > maximum_unix_ms:
            _d320_fail("d320_step_time_exceeds_updated")
        if step["file_fsync"] is not True or step["parent_fsync"] is not True:
            _d320_fail("d320_step_fsync_invalid")
        _d320_validate_evidence(step["readback"], aggregate=aggregate)
        _d320_validate_evidence(step["adapter_receipt"], aggregate=aggregate)
    elif any(
        item is not None
        for item in (
            ended,
            step["readback"],
            step["file_fsync"],
            step["parent_fsync"],
            step["adapter_receipt"],
        )
    ):
        _d320_fail("d320_step_completion_phase_invalid")
    inverse = step["inverse"]
    if status in ("INVERSE_INTENT", "INVERSE_VERIFIED") and inverse is None:
        _d320_fail("d320_step_inverse_missing")
    _d320_optional_evidence(inverse, aggregate=aggregate)
    return step


class StepV1(bytes):
    """A validated, immutable step carried by the bytes value itself."""

    __slots__ = ()

    def __new__(cls, payload_bytes: object) -> StepV1:
        payload_bytes = _d320_bytes_copy(
            payload_bytes, code="d320_wrapper_bytes_invalid"
        )
        _d320_immutable_mapping(payload_bytes, _d320_validate_step)
        return bytes.__new__(cls, payload_bytes)

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> StepV1:
        if cls is not StepV1:
            _d320_fail("d320_wrapper_factory_type_invalid")
        parsed = _d320_parse_json(_d320_canonical_json(value))
        _d320_validate_step(parsed)
        return StepV1(_d320_canonical_json(parsed))

    @property
    def status(self) -> str:
        return _d320_text(
            _d320_immutable_mapping(
                _d320_carrier_bytes(self, code="d320_wrapper_bytes_invalid"),
                _d320_validate_step,
            )["status"],
            maximum=32,
            ascii_only=True,
        )

    @property
    def index(self) -> int:
        return _d320_int(
            _d320_immutable_mapping(
                _d320_carrier_bytes(self, code="d320_wrapper_bytes_invalid"),
                _d320_validate_step,
            )["index"]
        )

    @property
    def has_inverse(self) -> bool:
        return (
            _d320_immutable_mapping(
                _d320_carrier_bytes(self, code="d320_wrapper_bytes_invalid"),
                _d320_validate_step,
            )["inverse"]
            is not None
        )

    def to_mapping(self) -> dict[str, object]:
        return _d320_immutable_mapping(
            _d320_carrier_bytes(self, code="d320_wrapper_bytes_invalid"),
            _d320_validate_step,
        )


def _d320_validate_source(value: object) -> Mapping[str, object]:
    source = _d320_object(
        value,
        ("commit", "tree", "plan_sha256", "decision_sha256", "generation"),
        code="d320_source_fields_invalid",
    )
    _d320_git_hex(source["commit"])
    _d320_git_hex(source["tree"])
    _d320_sha256(source["plan_sha256"])
    _d320_sha256(source["decision_sha256"])
    _d320_text(source["generation"], maximum=128, ascii_only=True)
    return source


def _d320_validate_digests(value: object) -> Mapping[str, object]:
    digests = _d320_object(
        value,
        (
            "runtime_manifest_sha256",
            "descriptor_sha256",
            "root_install_plan_sha256",
            "dispatch_allowlist_sha256",
            "hooks",
        ),
        code="d320_digest_fields_invalid",
    )
    for field in (
        "runtime_manifest_sha256",
        "descriptor_sha256",
        "root_install_plan_sha256",
        "dispatch_allowlist_sha256",
    ):
        _d320_sha256(digests[field])
    hooks = _d320_object(
        digests["hooks"],
        ("native_bee_event", "native_spawn_admission"),
        code="d320_hook_digest_fields_invalid",
    )
    _d320_sha256(hooks["native_bee_event"])
    _d320_sha256(hooks["native_spawn_admission"])
    return digests


def _d320_validate_parent_attestation(value: object) -> Mapping[str, object]:
    attestation = _d320_object(
        value,
        ("path", "dev", "ino", "uid", "gid", "mode", "nlink"),
        code="d320_parent_attestation_fields_invalid",
    )
    _d320_validate_absolute_path(attestation["path"])
    for field in ("dev", "ino", "uid", "gid"):
        _d320_int(attestation[field])
    _d320_int(attestation["mode"], maximum=0o7777)
    _d320_int(attestation["nlink"], minimum=1)
    return attestation


def _d320_validate_abi(value: object) -> Mapping[str, object]:
    abi = _d320_object(
        value,
        ("version", "expected_mode", "root_receipt"),
        code="d320_abi_fields_invalid",
    )
    if _d320_int(abi["version"]) != 1:
        _d320_fail("d320_abi_version_invalid")
    _d320_int(abi["expected_mode"], maximum=0o7777)
    receipt = _d320_object(
        abi["root_receipt"],
        (
            "dev",
            "ino",
            "uid",
            "gid",
            "mode",
            "nlink",
            "size",
            "sha256",
            "parent_chain",
            "file_fsync",
            "parent_fsync",
        ),
        code="d320_root_receipt_fields_invalid",
    )
    for field in ("dev", "ino", "uid", "gid", "size"):
        _d320_int(receipt[field])
    _d320_int(receipt["mode"], maximum=0o7777)
    if _d320_int(receipt["nlink"], minimum=1) != 1:
        _d320_fail("d320_root_receipt_nlink_invalid")
    _d320_sha256(receipt["sha256"])
    parents = receipt["parent_chain"]
    if not isinstance(parents, list) or not 1 <= len(parents) <= 32:
        _d320_fail("d320_parent_chain_invalid")
    for parent in parents:
        _d320_validate_parent_attestation(parent)
    if receipt["file_fsync"] is not True or receipt["parent_fsync"] is not True:
        _d320_fail("d320_root_receipt_fsync_invalid")
    return abi


def _d320_validate_native(
    value: object, *, aggregate: list[int]
) -> Mapping[str, object]:
    native = _d320_object(
        value,
        (
            "marketplace",
            "plugin",
            "cache",
            "hook_definition",
            "trust",
            "adapter_version",
            "request_id",
            "receipt_sha256",
            "disabled",
            "inverse",
        ),
        code="d320_native_fields_invalid",
    )
    for field in (
        "marketplace",
        "plugin",
        "cache",
        "hook_definition",
        "trust",
        "inverse",
    ):
        _d320_validate_evidence(native[field], aggregate=aggregate)
    _d320_text(native["adapter_version"], maximum=128, ascii_only=True)
    _d320_text(native["request_id"], maximum=128, ascii_only=True)
    _d320_sha256(native["receipt_sha256"])
    if not isinstance(native["disabled"], bool):
        _d320_fail("d320_native_disabled_invalid")
    return native


def _d320_validate_cutover(
    value: object, *, aggregate: list[int]
) -> Mapping[str, object]:
    cutover = _d320_object(
        value,
        (*_D320_SNAPSHOT_NAMES, "unit_status"),
        code="d320_cutover_fields_invalid",
    )
    for name in _D320_SNAPSHOT_NAMES:
        snapshot = _d320_validate_snapshot(cutover[name], aggregate=aggregate)
        if snapshot["name"] != name:
            _d320_fail("d320_snapshot_name_mismatch")
    _d320_validate_evidence(cutover["unit_status"], aggregate=aggregate)
    return cutover


def _d320_validate_lock_trace(
    value: object,
    *,
    state: str,
    sequence: int,
    history: Sequence[Mapping[str, object]],
) -> None:
    if not isinstance(value, list):
        _d320_fail("d320_lock_trace_invalid")
    held: list[str] = []
    acquired: set[str] = set()
    sublock_release_started = False
    journal_acquired = False
    journal_released = False
    prior_sequence: int | None = None
    for index, item in enumerate(value):
        entry = _d320_object(
            item,
            ("event", "lock", "state", "sequence"),
            code="d320_lock_event_fields_invalid",
        )
        event = _d320_text(entry["event"], maximum=16, ascii_only=True)
        lock = _d320_text(entry["lock"], maximum=64, ascii_only=True)
        event_state = _d320_text(entry["state"], maximum=64, ascii_only=True)
        event_sequence = _d320_int(entry["sequence"])
        if event not in ("ACQUIRE", "RELEASE") or lock not in D324_LOCK_ORDER:
            _d320_fail("d320_lock_event_invalid")
        if (
            event_state not in _D320_STATES
            or event_sequence > sequence
            or (prior_sequence is not None and event_sequence < prior_sequence)
        ):
            _d320_fail("d320_lock_event_binding_invalid")
        derived_state = "ABSENT"
        for transition in history:
            transition_sequence = _d320_int(transition["sequence"])
            if transition_sequence > event_sequence:
                break
            derived_state = str(transition["to"])
        if event_state != derived_state:
            _d320_fail("d320_lock_event_binding_invalid")
        prior_sequence = event_sequence
        if event == "ACQUIRE":
            if lock in acquired or journal_released:
                _d320_fail("d320_lock_reacquire_invalid")
            if lock != D324_LOCK_ORDER[0] and sublock_release_started:
                _d320_fail("d320_lock_order_invalid")
            if lock == D324_LOCK_ORDER[0]:
                if index != 0 or journal_acquired or event_state != "PREFLIGHTED":
                    _d320_fail("d320_journal_lock_acquire_invalid")
                journal_acquired = True
            elif not journal_acquired or not held:
                _d320_fail("d320_lock_order_invalid")
            elif D324_LOCK_ORDER.index(lock) <= D324_LOCK_ORDER.index(held[-1]):
                _d320_fail("d320_lock_order_invalid")
            held.append(lock)
            acquired.add(lock)
        else:
            if not held or held[-1] != lock:
                _d320_fail("d320_lock_release_invalid")
            if lock == D324_LOCK_ORDER[0]:
                if (
                    event_state != state
                    or event_sequence != sequence
                    or event_state not in _D320_TERMINAL_STATES
                ):
                    _d320_fail("d320_journal_lock_release_invalid")
                journal_released = True
            else:
                sublock_release_started = True
            held.pop()
    if state == "ABSENT":
        if value:
            _d320_fail("d320_absent_lock_trace_invalid")
    elif state in _D320_TERMINAL_STATES:
        direct_absent_block = (
            state == "BLOCKED"
            and len(history) == 1
            and history[0]["from"] == "ABSENT"
            and history[0]["to"] == "BLOCKED"
        )
        if direct_absent_block and not value:
            return
        if not journal_acquired or not journal_released or held:
            _d320_fail("d320_terminal_lock_trace_invalid")
    elif not journal_acquired or journal_released or D324_LOCK_ORDER[0] not in held:
        _d320_fail("d320_journal_lock_not_held")


def _d320_validate_pins(value: object) -> Mapping[str, object]:
    pins = _d320_object(
        value,
        ("current", "previous", "retained"),
        code="d320_pin_fields_invalid",
    )
    for field in ("current", "previous", "retained"):
        generations = pins[field]
        if not isinstance(generations, list) or len(generations) > 1024:
            _d320_fail("d320_pin_list_invalid")
        for generation in generations:
            _d320_text(generation, maximum=128, ascii_only=True)
        if (
            generations != sorted(generations)
            or len(generations) != len(set(generations))
        ):
            _d320_fail("d320_pin_list_not_canonical")
    return pins


def _d320_validate_history(
    value: object,
    *,
    state: str,
    sequence: int,
    maximum_unix_ms: int | None = None,
) -> None:
    if not isinstance(value, list) or len(value) > 256:
        _d320_fail("d320_history_invalid")
    if state == "ABSENT":
        if value:
            _d320_fail("d320_absent_history_invalid")
        return
    if not value:
        _d320_fail("d320_history_missing")
    previous = "ABSENT"
    previous_sequence: int | None = None
    previous_at: int | None = None
    for item in value:
        transition = _d320_validate_transition(item)
        transition_sequence = _d320_int(transition["sequence"])
        if transition["from"] != previous:
            _d320_fail("d320_history_not_continuous")
        if (
            transition_sequence < 1
            or (
                previous_sequence is not None
                and transition_sequence <= previous_sequence
            )
            or transition_sequence > sequence
        ):
            _d320_fail("d320_history_exceeds_record_sequence")
        at_unix_ms = _d320_int(transition["at_unix_ms"])
        if maximum_unix_ms is not None and at_unix_ms > maximum_unix_ms:
            _d320_fail("d320_history_time_exceeds_updated")
        if previous_at is not None and at_unix_ms < previous_at:
            _d320_fail("d320_history_time_invalid")
        previous = str(transition["to"])
        previous_sequence = transition_sequence
        previous_at = at_unix_ms
    if previous != state:
        _d320_fail("d320_history_state_mismatch")


def _d320_validate_steps(
    value: object, *, aggregate: list[int], state: str, maximum_unix_ms: int
) -> None:
    if not isinstance(value, list) or len(value) > 256:
        _d320_fail("d320_steps_invalid")
    statuses: list[str] = []
    for index, item in enumerate(value):
        step = _d320_validate_step(
            item, aggregate=aggregate, maximum_unix_ms=maximum_unix_ms
        )
        if step["index"] != index:
            _d320_fail("d320_step_index_invalid")
        statuses.append(str(step["status"]))
    inverse_statuses = {"INVERSE_INTENT", "INVERSE_VERIFIED"}
    if state in _D320_NORMAL_STATES:
        if any(status in inverse_statuses for status in statuses):
            _d320_fail("d320_normal_state_inverse_step_invalid")
        if any(status != "VERIFIED" for status in statuses[:-1]):
            _d320_fail("d320_step_predecessor_not_terminal")
        return
    if state == "ROLLED_BACK":
        if any(status != "INVERSE_VERIFIED" for status in statuses):
            _d320_fail("d320_rolled_back_steps_invalid")
        return
    if state not in ("ABORTING", "BLOCKED"):
        return
    rollback_phase = "VERIFIED"
    for status in statuses:
        if rollback_phase == "VERIFIED" and status == "VERIFIED":
            continue
        if status == "INVERSE_INTENT" and rollback_phase == "VERIFIED":
            rollback_phase = "INVERSE_INTENT"
            continue
        if status == "INVERSE_VERIFIED" and rollback_phase in (
            "VERIFIED",
            "INVERSE_INTENT",
            "INVERSE_VERIFIED",
        ):
            rollback_phase = "INVERSE_VERIFIED"
            continue
        if status == "INVERSE_INTENT":
            if rollback_phase != "VERIFIED":
                _d320_fail("d320_rollback_step_form_invalid")
        _d320_fail("d320_rollback_step_form_invalid")


def _d320_validate_payload(
    value: object, *, budget: _D320JsonTraversalBudget | None = None
) -> Mapping[str, object]:
    _d320_json_value(value, budget=budget)
    payload = _d320_object(
        value,
        (
            "schema",
            "journal_id",
            "sequence",
            "state",
            "controller",
            "created_unix_ms",
            "updated_unix_ms",
            "recovery_count",
            "source",
            "digests",
            "abi",
            "native",
            "precutover",
            "postcutover",
            "pins",
            "history",
            "steps",
            "lock_trace",
        ),
        code="d320_payload_fields_invalid",
    )
    if payload["schema"] != _D320_SCHEMA:
        _d320_fail("d320_schema_invalid")
    _d320_text(payload["journal_id"], maximum=128, ascii_only=True)
    sequence = _d320_int(payload["sequence"])
    state = _d320_text(payload["state"], maximum=64, ascii_only=True)
    if state not in _D320_STATES:
        _d320_fail("d320_state_invalid")
    _d320_text(payload["controller"], maximum=128, ascii_only=True)
    created = _d320_int(payload["created_unix_ms"])
    updated = _d320_int(payload["updated_unix_ms"])
    if updated < created:
        _d320_fail("d320_updated_before_created")
    _d320_int(payload["recovery_count"], maximum=1024)
    _d320_validate_source(payload["source"])
    _d320_validate_digests(payload["digests"])
    _d320_validate_abi(payload["abi"])
    aggregate = [0]
    _d320_validate_native(payload["native"], aggregate=aggregate)
    precutover = _d320_validate_cutover(payload["precutover"], aggregate=aggregate)
    postcutover = _d320_validate_cutover(payload["postcutover"], aggregate=aggregate)
    if all(
        precutover[name] == postcutover[name] for name in _D320_ARTIFACT_NAMES
    ):
        _d320_fail("d320_cutover_artifacts_ambiguous")
    _d320_validate_history(
        payload["history"],
        state=state,
        sequence=sequence,
        maximum_unix_ms=updated,
    )
    _d320_validate_steps(
        payload["steps"],
        aggregate=aggregate,
        state=state,
        maximum_unix_ms=updated,
    )
    _d320_validate_pins(payload["pins"])
    _d320_validate_lock_trace(
        payload["lock_trace"],
        state=state,
        sequence=sequence,
        history=payload["history"],
    )
    if state in (
        "USER_CUTOVER_VERIFIED",
        "ISOLATED_HOOK_PROBE_VERIFIED",
        "MCP_HANDSHAKE_VERIFIED",
        "LIVE_GRANTED",
    ) and (
        not payload["steps"]
        or any(step["status"] != "VERIFIED" for step in payload["steps"])
    ):
        _d320_fail("d320_user_cutover_steps_invalid")
    return payload


def _d320_journal_payload_from_carrier(
    value: object, *, budget: _D320JsonTraversalBudget | None = None
) -> tuple[bytes, dict[str, object]]:
    traversal_budget = budget or _D320JsonTraversalBudget()
    payload_bytes = _d320_validate_envelope_payload_size(
        _d320_carrier_bytes(value, code="d320_payload_bytes_invalid")
    )
    parsed = _d320_parse_json(payload_bytes)
    if not isinstance(parsed, dict):
        _d320_fail("d320_payload_mapping_invalid")
    _d320_validate_payload(parsed, budget=traversal_budget)
    if _d320_canonical_json(parsed, budget=traversal_budget) != payload_bytes:
        _d320_fail("d320_payload_not_canonical")
    return payload_bytes, parsed


def _d320_journal_envelope(payload_bytes: bytes) -> bytes:
    digest = hashlib.sha256(payload_bytes).hexdigest().encode("ascii")
    return (
        b'{"content_sha256":"'
        + digest
        + b'","payload":'
        + payload_bytes
        + b"}\n"
    )


class D320CutoverJournalV1(bytes):
    """A validated, immutable journal payload carried by the bytes value itself."""

    __slots__ = ()

    def __new__(
        cls,
        payload_bytes: object,
        *,
        budget: _D320JsonTraversalBudget | None = None,
    ) -> D320CutoverJournalV1:
        traversal_budget = budget or _D320JsonTraversalBudget()
        payload_bytes = _d320_validate_envelope_payload_size(payload_bytes)
        parsed = _d320_parse_json(payload_bytes)
        _d320_validate_payload(parsed, budget=traversal_budget)
        if _d320_canonical_json(parsed, budget=traversal_budget) != payload_bytes:
            _d320_fail("d320_payload_not_canonical")
        return bytes.__new__(cls, payload_bytes)

    @classmethod
    def from_payload(
        cls,
        value: Mapping[str, object],
        *,
        budget: _D320JsonTraversalBudget | None = None,
    ) -> D320CutoverJournalV1:
        if cls is not D320CutoverJournalV1:
            _d320_fail("d320_journal_factory_type_invalid")
        traversal_budget = budget or _D320JsonTraversalBudget()
        payload_bytes = _d320_canonical_json(value, budget=traversal_budget)
        _d320_validate_envelope_payload_size(payload_bytes)
        parsed = _d320_parse_json(payload_bytes)
        _d320_validate_payload(parsed, budget=traversal_budget)
        if len(_d320_journal_envelope(payload_bytes)) > _D320_MAX_ENVELOPE_BYTES:
            _d320_fail("d320_envelope_too_large")
        return D320CutoverJournalV1(payload_bytes, budget=traversal_budget)

    @classmethod
    def from_bytes(
        cls,
        raw: bytes,
        *,
        budget: _D320JsonTraversalBudget | None = None,
    ) -> D320CutoverJournalV1:
        if cls is not D320CutoverJournalV1:
            _d320_fail("d320_journal_factory_type_invalid")
        traversal_budget = budget or _D320JsonTraversalBudget()
        raw = _d320_bytes_copy(raw, code="d320_envelope_size_invalid")
        if len(raw) > _D320_MAX_ENVELOPE_BYTES:
            _d320_fail("d320_envelope_size_invalid")
        if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
            _d320_fail("d320_envelope_lf_invalid")
        envelope = _d320_parse_json(raw[:-1])
        _d320_json_value(envelope, semantic=False, budget=traversal_budget)
        if not isinstance(envelope, dict) or set(envelope) != {
            "content_sha256",
            "payload",
        }:
            _d320_fail("d320_envelope_fields_invalid")
        payload = envelope["payload"]
        payload_bytes = _d320_syntax_json(payload, budget=traversal_budget)
        if envelope["content_sha256"] != hashlib.sha256(payload_bytes).hexdigest():
            _d320_fail("d320_envelope_digest_invalid")
        payload_bytes = _d320_canonical_json(payload, budget=traversal_budget)
        journal = D320CutoverJournalV1(payload_bytes, budget=traversal_budget)
        if raw != _d320_journal_envelope(payload_bytes):
            _d320_fail("d320_envelope_not_canonical")
        return journal

    @property
    def payload_bytes(self) -> bytes:
        payload_bytes, _ = _d320_journal_payload_from_carrier(self)
        return payload_bytes

    @property
    def payload(self) -> dict[str, object]:
        _, parsed = _d320_journal_payload_from_carrier(self)
        return parsed

    def to_bytes(self) -> bytes:
        payload_bytes, _ = _d320_journal_payload_from_carrier(self)
        return _d320_journal_envelope(payload_bytes)


def validate_d320_journal_successor(
    previous: D320CutoverJournalV1,
    successor: D320CutoverJournalV1,
    *,
    recovery_entry: bool = False,
    observed: Mapping[str, object] | None = None,
) -> None:
    if not isinstance(previous, D320CutoverJournalV1) or not isinstance(
        successor, D320CutoverJournalV1
    ):
        _d320_fail("d320_successor_type_invalid")
    if type(recovery_entry) is not bool:
        _d320_fail("d320_recovery_entry_invalid")
    try:
        previous = D320CutoverJournalV1(memoryview(previous).tobytes())
        successor = D320CutoverJournalV1(memoryview(successor).tobytes())
    except (D320CutoverJournalError, MemoryError, TypeError) as exc:
        raise D320CutoverJournalError("d320_successor_revalidation_invalid") from exc
    before = D320CutoverJournalV1.payload.fget(previous)
    after = D320CutoverJournalV1.payload.fget(successor)
    if (
        after["journal_id"] != before["journal_id"]
        or after["controller"] != before["controller"]
    ):
        _d320_fail("d320_successor_identity_changed")
    if any(
        after[field] != before[field]
        for field in (
            "created_unix_ms",
            "source",
            "digests",
            "abi",
            "native",
            "precutover",
            "postcutover",
            "pins",
        )
    ):
        _d320_fail("d320_successor_static_binding_changed")
    if int(after["sequence"]) != int(before["sequence"]) + 1:
        _d320_fail("d320_successor_sequence_invalid")
    if int(after["updated_unix_ms"]) < int(before["updated_unix_ms"]):
        _d320_fail("d320_successor_time_invalid")
    before_recovery = int(before["recovery_count"])
    after_recovery = int(after["recovery_count"])
    if recovery_entry:
        if after_recovery != before_recovery + 1:
            _d320_fail("d320_recovery_counter_invalid")
    elif after_recovery != before_recovery:
        _d320_fail("d320_recovery_counter_invalid")
    before_history = before["history"]
    after_history = after["history"]
    before_steps = before["steps"]
    after_steps = after["steps"]
    before_trace = before["lock_trace"]
    after_trace = after["lock_trace"]
    assert isinstance(before_history, list) and isinstance(after_history, list)
    assert isinstance(before_steps, list) and isinstance(after_steps, list)
    assert isinstance(before_trace, list) and isinstance(after_trace, list)
    if after_history[: len(before_history)] != before_history:
        _d320_fail("d320_history_rewrite_invalid")
    if after_trace[: len(before_trace)] != before_trace:
        _d320_fail("d320_lock_trace_rewrite_invalid")
    if any(
        int(event["sequence"]) != int(after["sequence"])
        for event in after_trace[len(before_trace) :]
    ):
        _d320_fail("d320_lock_event_generation_invalid")
    state_changed = after["state"] != before["state"]
    steps_changed = after_steps != before_steps
    if state_changed:
        if steps_changed or len(after_history) != len(before_history) + 1:
            _d320_fail("d320_successor_transition_invalid")
        transition = after_history[-1]
        if (
            transition["from"] != before["state"]
            or transition["to"] != after["state"]
            or int(transition["sequence"]) != int(after["sequence"])
            or not _d320_transition_allowed(str(before["state"]), str(after["state"]))
        ):
            _d320_fail("d320_successor_transition_invalid")
        if before_steps and any(
            step["status"] not in ("VERIFIED", "INVERSE_VERIFIED")
            for step in before_steps
        ):
            _d320_fail("d320_state_before_step_terminal")
        if after["state"] == "ROLLED_BACK" and any(
            step["status"] != "INVERSE_VERIFIED" for step in before_steps
        ):
            _d320_fail("d320_rollback_steps_not_inverted")
    elif after_history != before_history:
        _d320_fail("d320_history_append_invalid")
    if steps_changed:
        if state_changed:
            _d320_fail("d320_step_state_change_invalid")
        if len(after_steps) == len(before_steps) + 1:
            new_step = after_steps[-1]
            if (
                before["state"] == "ABORTING"
                or after_steps[: len(before_steps)] != before_steps
                or new_step["status"] != "INTENT"
                or any(
                    step["status"] not in ("VERIFIED", "INVERSE_VERIFIED")
                    for step in before_steps
                )
            ):
                _d320_fail("d320_step_append_invalid")
        elif len(after_steps) == len(before_steps) and before_steps:
            changed = [
                index
                for index, (before_step, after_step) in enumerate(
                    zip(before_steps, after_steps)
                )
                if before_step != after_step
            ]
            if len(changed) != 1:
                _d320_fail("d320_step_rewrite_invalid")
            index = changed[0]
            before_step = before_steps[index]
            after_step = after_steps[index]
            fill_fields = {
                ("INTENT", "EFFECT_STARTED"): {"effect_started_unix_ms"},
                ("EFFECT_STARTED", "VERIFIED"): {
                    "effect_ended_unix_ms",
                    "readback",
                    "file_fsync",
                    "parent_fsync",
                    "adapter_receipt",
                },
                ("VERIFIED", "INVERSE_INTENT"): {"inverse"},
            }.get((before_step["status"], after_step["status"]), set())
            for field, before_value in before_step.items():
                if field == "status":
                    continue
                after_value = after_step[field]
                if before_value is not None and after_value != before_value:
                    _d320_fail("d320_step_rewrite_invalid")
                if before_value is None and (
                    after_value is not None and field not in fill_fields
                ):
                    _d320_fail("d320_step_rewrite_invalid")
            if before["state"] == "ABORTING":
                unresolved = [
                    item_index
                    for item_index, step in enumerate(before_steps)
                    if step["status"] != "INVERSE_VERIFIED"
                ]
                if not unresolved or index != unresolved[-1] or any(
                    before_steps[item_index]["status"] != "VERIFIED"
                    for item_index in unresolved[:-1]
                ):
                    _d320_fail("d320_inverse_order_invalid")
                allowed = {
                    "VERIFIED": "INVERSE_INTENT",
                    "INVERSE_INTENT": "INVERSE_VERIFIED",
                }
            else:
                if index != len(before_steps) - 1:
                    _d320_fail("d320_step_phase_invalid")
                allowed = {
                    "INTENT": "EFFECT_STARTED",
                    "EFFECT_STARTED": "VERIFIED",
                }
            if allowed.get(before_step["status"]) != after_step["status"]:
                _d320_fail("d320_step_phase_invalid")
        else:
            _d320_fail("d320_step_append_invalid")
    elif len(after_steps) < len(before_steps) or len(after_steps) > len(before_steps):
        _d320_fail("d320_step_rewrite_invalid")
    if state_changed and after["state"] == "BLOCKED":
        budget = _D320JsonTraversalBudget()
        stable_observed = _d320_normalize_observed_artifact_input(
            observed, budget=budget
        )
        classification = _d320_classify_d320_recovery(
            successor,
            observed=stable_observed,
            budget=budget,
            strict_budget=True,
        )
        reason = after_history[-1]["reason_code"]
        if _D320_ABORT_BLOCK_REASONS.get(reason) != classification.kind:
            _d320_fail("d320_block_recovery_mismatch")
    elif observed is not None:
        _d320_fail("d320_successor_observed_unexpected")


def validate_d324_lock_order(
    trace: Sequence[Mapping[str, object]],
    *,
    state: str,
    sequence: int,
    history: Sequence[Mapping[str, object]],
) -> None:
    state_text = _d320_text(state, maximum=64, ascii_only=True)
    if state_text not in _D320_STATES:
        _d320_fail("d320_state_invalid")
    sequence_value = _d320_int(sequence)
    traversal_budget = _D320JsonTraversalBudget()
    history_value = _d320_sequence_copy(
        history,
        maximum=256,
        code="d320_history_invalid",
        budget=traversal_budget,
    )
    trace_value = _d320_sequence_copy(
        trace,
        maximum=2 * len(D324_LOCK_ORDER),
        code="d320_lock_trace_invalid",
        budget=traversal_budget,
    )
    _d320_validate_history(
        history_value, state=state_text, sequence=sequence_value
    )
    _d320_validate_lock_trace(
        trace_value,
        state=state_text,
        sequence=sequence_value,
        history=history_value,
    )


@dataclass(frozen=True, slots=True)
class RecoveryClassificationV1:
    kind: str
    state: str
    inverse_step_indexes: tuple[int, ...]


def _d320_artifact_mapping(
    value: object,
    *,
    budget: _D320JsonTraversalBudget | None = None,
    strict_budget: bool = False,
) -> dict[str, object] | None:
    try:
        if not _d320_artifact_shape(value, budget=budget):
            return None
        result: dict[str, object] = {}
        for name in _D320_SNAPSHOT_NAMES:
            snapshot = value[name]
            if isinstance(snapshot, ByteSnapshotV1):
                mapping = ByteSnapshotV1.to_mapping(snapshot)
            elif isinstance(snapshot, Mapping):
                parsed = _d320_parse_json(
                    _d320_canonical_json(snapshot, budget=budget)
                )
                if not isinstance(parsed, dict):
                    return None
                mapping = parsed
            else:
                return None
            if isinstance(snapshot, ByteSnapshotV1):
                _d320_json_value(mapping, budget=budget)
            result[name] = ByteSnapshotV1.from_mapping(mapping)
        unit_status = value["unit_status"]
        if isinstance(unit_status, EvidenceBlobV1):
            mapping = EvidenceBlobV1.to_mapping(unit_status)
        elif isinstance(unit_status, Mapping):
            parsed = _d320_parse_json(
                _d320_canonical_json(unit_status, budget=budget)
            )
            if not isinstance(parsed, dict):
                return None
            mapping = parsed
        else:
            return None
        if isinstance(unit_status, EvidenceBlobV1):
            _d320_json_value(mapping, budget=budget)
        result["unit_status"] = EvidenceBlobV1.from_mapping(mapping)
    except D320CutoverJournalError as exc:
        if strict_budget and _d320_budget_error(exc):
            raise
        return None
    except (AttributeError, KeyError, MemoryError):
        return None
    except Exception:
        return None
    return result


def _d320_normalize_observed_artifact_input(
    value: object, *, budget: _D320JsonTraversalBudget
) -> dict[str, object]:
    """Take one bounded, stable copy of observed artifacts for recovery."""

    if not isinstance(value, Mapping):
        _d320_fail("d320_block_observed_required")
    try:
        if not _d320_artifact_shape(value, budget=budget):
            _d320_fail("d320_block_observed_required")
        raw = {name: value[name] for name in _D320_ARTIFACT_NAMES}
        stable: dict[str, object] = {}
        for name in _D320_SNAPSHOT_NAMES:
            snapshot = raw[name]
            if isinstance(snapshot, ByteSnapshotV1):
                snapshot = ByteSnapshotV1.to_mapping(snapshot)
            if isinstance(snapshot, Mapping):
                snapshot = _d320_normalize_json_value(snapshot, budget=budget)
            stable[name] = snapshot
        unit_status = raw["unit_status"]
        if isinstance(unit_status, EvidenceBlobV1):
            unit_status = EvidenceBlobV1.to_mapping(unit_status)
        if isinstance(unit_status, Mapping):
            unit_status = _d320_normalize_json_value(unit_status, budget=budget)
        stable["unit_status"] = unit_status
        return stable
    except D320CutoverJournalError:
        raise
    except MemoryError as exc:
        raise D320CutoverJournalError("d320_block_observed_required") from exc
    except Exception as exc:
        raise D320CutoverJournalError("d320_block_observed_required") from exc


def _d320_artifact_shape(
    value: object, *, budget: _D320JsonTraversalBudget | None = None
) -> bool:
    try:
        if not isinstance(value, Mapping) or len(value) != len(_D320_ARTIFACT_NAMES):
            return False
        keys: set[str] = set()
        iterator = iter(value)
        for _index in range(len(_D320_ARTIFACT_NAMES) + 1):
            try:
                key = next(iterator)
            except StopIteration:
                break
            if budget is not None:
                _d320_visit_json_entry(budget)
            if _index == len(_D320_ARTIFACT_NAMES):
                return False
            if not isinstance(key, str) or key not in _D320_ARTIFACT_NAMES:
                return False
            keys.add(key)
        return len(keys) == len(_D320_ARTIFACT_NAMES)
    except D320CutoverJournalError:
        raise
    except MemoryError:
        return False
    except Exception:
        return False


def _d320_classify_d320_recovery(
    journal: D320CutoverJournalV1 | bytes,
    *,
    observed: Mapping[str, object],
    budget: _D320JsonTraversalBudget | None = None,
    strict_budget: bool = False,
) -> RecoveryClassificationV1:
    try:
        if isinstance(journal, D320CutoverJournalV1):
            journal_bytes, _ = _d320_journal_payload_from_carrier(journal)
            journal = _d320_journal_envelope(journal_bytes)
        model = D320CutoverJournalV1.from_bytes(journal)
        if not isinstance(model, D320CutoverJournalV1):
            raise D320CutoverJournalError("d320_recovery_journal_invalid")
        payload = D320CutoverJournalV1.payload.fget(model)
        seen = _d320_artifact_mapping(
            observed, budget=budget, strict_budget=strict_budget
        )
        old = _d320_artifact_mapping(payload["precutover"])
        new = _d320_artifact_mapping(payload["postcutover"])
        if old is None or seen is None or new is None:
            raise D320CutoverJournalError("d320_recovery_snapshots_invalid")
    except D320CutoverJournalError as exc:
        if strict_budget and _d320_budget_error(exc):
            raise
        return RecoveryClassificationV1("UNREADABLE_BLOCKED", "BLOCKED", ())
    except (AttributeError, KeyError, MemoryError):
        return RecoveryClassificationV1("UNREADABLE_BLOCKED", "BLOCKED", ())
    except Exception:
        return RecoveryClassificationV1("UNREADABLE_BLOCKED", "BLOCKED", ())

    if all(seen[name] == old[name] for name in _D320_ARTIFACT_NAMES):
        return RecoveryClassificationV1("ALL_OLD_VERIFIED", "ROLLED_BACK", ())
    steps = payload["steps"]
    assert isinstance(steps, list)
    if all(seen[name] == new[name] for name in _D320_ARTIFACT_NAMES) and (
        payload["state"]
        in (
            "USER_CUTOVER_VERIFIED",
            "ISOLATED_HOOK_PROBE_VERIFIED",
            "MCP_HANDSHAKE_VERIFIED",
            "LIVE_GRANTED",
        )
        and bool(steps)
        and all(
            isinstance(step, Mapping) and step["status"] == "VERIFIED"
            for step in steps
        )
    ):
        return RecoveryClassificationV1(
            "ALL_NEW_VERIFIED", "USER_CUTOVER_VERIFIED", ()
        )
    if any(
        seen[name] != old[name] and seen[name] != new[name]
        for name in _D320_ARTIFACT_NAMES
    ):
        return RecoveryClassificationV1("MIXED_BLOCKED", "BLOCKED", ())
    if not steps or any(
        not isinstance(step, Mapping)
        or step["status"] not in ("VERIFIED", "INVERSE_VERIFIED")
        or step["inverse"] is None
        for step in steps
    ):
        return RecoveryClassificationV1("NONINVERTIBLE_BLOCKED", "BLOCKED", ())
    inverse_indexes = tuple(
        int(step["index"])
        for step in reversed(steps)
        if step["status"] == "VERIFIED"
    )
    if not inverse_indexes:
        return RecoveryClassificationV1("NONINVERTIBLE_BLOCKED", "BLOCKED", ())
    return RecoveryClassificationV1("MIXED_INVERTIBLE", "ABORTING", inverse_indexes)


def classify_d320_recovery(
    journal: D320CutoverJournalV1 | bytes,
    *,
    observed: Mapping[str, object],
) -> RecoveryClassificationV1:
    try:
        budget = _D320JsonTraversalBudget()
        stable_observed = _d320_normalize_observed_artifact_input(
            observed, budget=budget
        )
    except (AttributeError, D320CutoverJournalError, KeyError, MemoryError):
        return RecoveryClassificationV1("UNREADABLE_BLOCKED", "BLOCKED", ())
    except Exception:
        return RecoveryClassificationV1("UNREADABLE_BLOCKED", "BLOCKED", ())
    return _d320_classify_d320_recovery(
        journal, observed=stable_observed, budget=budget
    )


@dataclass(frozen=True, slots=True)
class _BoundCutover:
    home: Path
    release_root: Path
    units: Path
    state_root: Path
    files: tuple[tuple[Path, bytes | None, int], ...]
    source_digests: tuple[tuple[Path, str], ...]
    source_commit: str
    generations_before: frozenset[str]
    legacy_present: bool
    states: tuple[tuple[str, Mapping[str, str]], ...]
    source_tree_digest: str = ""


@dataclass(frozen=True, slots=True)
class _RollbackResult:
    """A fixed, data-sparse outcome for the compensating transaction."""

    restored: bool
    phase: str
    error_code: str


@dataclass(frozen=True, slots=True)
class _ProbeObservationBinding:
    """The installed, argumentless launcher and its current attested image."""

    generation: str
    manifest_digest: str
    launcher_sha256: str
    launcher: Path
    runtime_layout: object


@dataclass(frozen=True, slots=True)
class _PostInstallBinding:
    """The new attested image and pair of installed units before manager use."""

    identity: tuple[str, str]
    service: bytes
    timer: bytes


@dataclass(frozen=True, slots=True)
class _InstallerEntry:
    descriptor: int
    identity: tuple[int, int, int, int, int]
    digest: str


@dataclass(frozen=True, slots=True)
class _CanaryImage:
    """One unpublished-authority image and its private diagnostic state."""

    invocation_root: Path
    release_root: Path
    state_root: Path
    generation: str
    manifest_digest: str
    service: bytes


@dataclass(frozen=True, slots=True)
class _CanaryUnitBinding:
    """The exact transient unit identity and transformed hourly contract."""

    name: str
    description: str
    home: Path
    properties: tuple[str, ...]
    command: tuple[str, ...]

    @property
    def run_arguments(self) -> tuple[str, ...]:
        return (
            f"--unit={self.name}",
            f"--description={self.description}",
            "--no-block",
            "--no-ask-password",
            "--expand-environment=no",
            "--service-type=oneshot",
            f"--working-directory={self.home}",
            f"--setenv=HOME={self.home}",
            "--setenv=LANG=C",
            "--setenv=PATH=/usr/bin:/bin",
            *(f"--property={value}" for value in self.properties),
            "--",
            *self.command,
        )


def _home_paths(home: Path) -> tuple[Path, Path, Path, Path]:
    if not isinstance(home, Path) or not home.is_absolute():
        raise _error("runtime_lifecycle_home_invalid")
    return (
        home / ".local" / "lib" / "the-hive-runtime",
        home / ".config" / "systemd" / "user",
        home / ".local" / "state" / "codex-master-mcp",
        home / ".local" / "libexec" / "codex_master_hive_hourly_probe.py",
    )


def _private_directory(path: Path) -> None:
    try:
        item = path.lstat()
    except OSError as exc:
        raise _error("runtime_lifecycle_lock_invalid") from exc
    if (
        stat.S_ISLNK(item.st_mode)
        or not stat.S_ISDIR(item.st_mode)
        or item.st_uid != os.geteuid()
        or stat.S_IMODE(item.st_mode) != 0o700
    ):
        raise _error("runtime_lifecycle_lock_invalid")


def _bound_path_from_home(home: Path, path: Path) -> None:
    """Reject a symlink or writable parent in an existing home-relative path."""

    try:
        relative = path.relative_to(home)
    except ValueError as exc:
        raise _error("runtime_lifecycle_binding_invalid") from exc
    current = home
    try:
        root = current.lstat()
    except OSError as exc:
        raise _error("runtime_lifecycle_binding_invalid") from exc
    if (
        stat.S_ISLNK(root.st_mode)
        or not stat.S_ISDIR(root.st_mode)
        or root.st_uid != os.geteuid()
    ):
        raise _error("runtime_lifecycle_binding_invalid")
    for part in relative.parts:
        current /= part
        try:
            item = current.lstat()
        except FileNotFoundError:
            return
        except OSError as exc:
            raise _error("runtime_lifecycle_binding_invalid") from exc
        if stat.S_ISLNK(item.st_mode):
            raise _error("runtime_lifecycle_binding_invalid")
        if current != path and (
            not stat.S_ISDIR(item.st_mode)
            or item.st_uid != os.geteuid()
            or stat.S_IMODE(item.st_mode) & 0o022
        ):
            raise _error("runtime_lifecycle_binding_invalid")


def _regular_bytes(
    path: Path, *, maximum: int, mode: int | None = None
) -> bytes | None:
    """Read one own, no-follow regular file or return absent; reject all else."""

    descriptor = -1
    try:
        before = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise _error("runtime_lifecycle_binding_invalid") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_uid != os.geteuid()
        or before.st_size <= 0
        or before.st_size > maximum
        or (mode is not None and stat.S_IMODE(before.st_mode) != mode)
    ):
        raise _error("runtime_lifecycle_binding_invalid")
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_uid != before.st_uid
            or opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
            or opened.st_size != before.st_size
            or (mode is not None and stat.S_IMODE(opened.st_mode) != mode)
        ):
            raise _error("runtime_lifecycle_binding_invalid")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        value = b"".join(chunks)
        after = os.fstat(descriptor)
    except RuntimeLifecycleError:
        raise
    except OSError as exc:
        raise _error("runtime_lifecycle_binding_invalid") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if (
        len(value) != before.st_size
        or after.st_ino != before.st_ino
        or len(value) > maximum
    ):
        raise _error("runtime_lifecycle_binding_invalid")
    return value


def _source_digest(path: Path) -> str:
    value = _regular_bytes(path, maximum=2 * 1024 * 1024)
    if value is None:
        raise _error("runtime_lifecycle_source_invalid")
    try:
        item = path.lstat()
    except OSError as exc:
        raise _error("runtime_lifecycle_source_invalid") from exc
    if stat.S_IMODE(item.st_mode) & 0o022:
        raise _error("runtime_lifecycle_source_invalid")
    return hashlib.sha256(value).hexdigest()


def _source_tree_binding(repository: Path) -> tuple[str, str]:
    """Bind the entire clean tracked tree, not a selected source-file subset."""

    command_env = {"LANG": "C", "PATH": "/usr/bin:/bin"}
    commands = (
        ("status", "--porcelain=v1", "-z"),
        ("rev-parse", "--verify", "HEAD^{commit}"),
        ("rev-parse", "--verify", "HEAD^{tree}"),
        ("ls-tree", "-r", "-z", "HEAD"),
    )
    values: list[bytes] = []
    try:
        for arguments in commands:
            completed = subprocess.run(
                ["git", "-C", os.fspath(repository), *arguments],
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=command_env,
            )
            if completed.returncode != 0:
                raise _error("runtime_lifecycle_source_invalid")
            values.append(completed.stdout)
    except OSError as exc:
        raise _error("runtime_lifecycle_source_invalid") from exc
    status, commit_raw, tree_raw, closure = values
    try:
        commit = commit_raw.decode("ascii", errors="strict").strip()
        tree = tree_raw.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise _error("runtime_lifecycle_source_invalid") from exc
    if (
        status
        or len(commit) != 40
        or len(tree) != 40
        or any(character not in "0123456789abcdef" for character in commit + tree)
        or not closure
    ):
        raise _error("runtime_lifecycle_source_dirty")
    return commit, hashlib.sha256(tree.encode("ascii") + b"\0" + closure).hexdigest()


@contextmanager
def _bound_installer_entry(repository: Path):
    """Hold the installer source FD across path loading and verify its identity."""

    path = repository / "scripts" / "the-hive-hive-hourly-probe-install"
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o022
            or before.st_size <= 0
            or before.st_size > 2 * 1024 * 1024
        ):
            raise _error("runtime_lifecycle_source_entry_invalid")
        raw = bytearray()
        while len(raw) <= 2 * 1024 * 1024:
            part = os.read(descriptor, min(65536, 2 * 1024 * 1024 + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
        after = os.fstat(descriptor)
        identity = (
            before.st_dev,
            before.st_ino,
            before.st_uid,
            stat.S_IMODE(before.st_mode),
            before.st_nlink,
        )
        if (
            len(raw) != before.st_size
            or len(raw) > 2 * 1024 * 1024
            or identity
            != (
                after.st_dev,
                after.st_ino,
                after.st_uid,
                stat.S_IMODE(after.st_mode),
                after.st_nlink,
            )
        ):
            raise _error("runtime_lifecycle_source_entry_invalid")
        yield _InstallerEntry(
            descriptor=descriptor,
            identity=identity,
            digest=hashlib.sha256(raw).hexdigest(),
        )
        current = path.lstat()
        if (
            current.st_dev,
            current.st_ino,
            current.st_uid,
            stat.S_IMODE(current.st_mode),
            current.st_nlink,
        ) != identity or _source_digest(path) != hashlib.sha256(raw).hexdigest():
            raise _error("runtime_lifecycle_source_entry_changed")
    except RuntimeLifecycleError:
        raise
    except OSError as exc:
        raise _error("runtime_lifecycle_source_entry_invalid") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _prepare_canary_image(
    *, repository: Path, invocation_root: Path, source_commit: str
) -> _CanaryImage:
    """Build and publish one complete image only below the disposable root."""

    if (
        not isinstance(repository, Path)
        or not repository.is_absolute()
        or not isinstance(invocation_root, Path)
        or not invocation_root.is_absolute()
        or len(source_commit) != 40
        or any(character not in "0123456789abcdef" for character in source_commit)
    ):
        raise _error("runtime_canary_image_invalid")
    _private_directory(invocation_root)
    try:
        with _bound_installer_entry(repository) as entry:
            installer = runpy.run_path(f"/proc/self/fd/{entry.descriptor}")
            build = installer.get("_build_runtime_image")
            publish = installer.get("_publish_runtime_generation")
            if not callable(build) or not callable(publish):
                raise _error("runtime_canary_image_invalid")
            stage = Path(
                tempfile.mkdtemp(prefix=".stage-", dir=os.fspath(invocation_root))
            )
            local_root = invocation_root / ".local"
            library_root = local_root / "lib"
            state_parent = local_root / "state"
            state_root = state_parent / "codex-master-mcp"
            for directory in (local_root, library_root, state_parent, state_root):
                directory.mkdir(mode=0o700)
            release_root = library_root / "the-hive-runtime"
            _private_directory(stage)
            for directory in (local_root, library_root, state_parent):
                _private_directory(directory)
            _private_directory(state_root)
            build(
                repository=repository,
                stage=stage,
                generation=source_commit,
                commit=source_commit,
            )
            layout = publish(stage=stage, release_root=release_root)
            manifest_digest = getattr(layout, "manifest_digest", None)
            layout_root = getattr(layout, "root", None)
            if (
                not isinstance(manifest_digest, str)
                or len(manifest_digest) != 71
                or not manifest_digest.startswith("sha256:")
                or any(
                    character not in "0123456789abcdef"
                    for character in manifest_digest.removeprefix("sha256:")
                )
                or layout_root
                != release_root / "generations" / source_commit
            ):
                raise _error("runtime_canary_image_invalid")
            service, _timer = _attested_hourly_unit_bytes(
                release_root=release_root,
                generation=source_commit,
                manifest_digest=manifest_digest,
            )
    except RuntimeLifecycleError:
        raise
    except Exception as exc:
        raise _error("runtime_canary_image_invalid") from exc
    return _CanaryImage(
        invocation_root=invocation_root,
        release_root=release_root,
        state_root=state_root,
        generation=source_commit,
        manifest_digest=manifest_digest,
        service=service,
    )


def _unit_directives(raw: bytes) -> Mapping[str, tuple[str, ...]]:
    """Parse only the tiny, exact unit grammar needed for Canary derivation."""

    if not raw or len(raw) > _MAX_UNIT_BYTES or b"\x00" in raw:
        raise _error("runtime_canary_sandbox_invalid")
    try:
        lines = raw.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as exc:
        raise _error("runtime_canary_sandbox_invalid") from exc
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for line in lines:
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
            if current not in {"Unit", "Service"} or current in sections:
                raise _error("runtime_canary_sandbox_invalid")
            sections[current] = []
            continue
        key, separator, _value = line.partition("=")
        if (
            current is None
            or not separator
            or not key
            or line != line.strip()
            or len(line) > 4096
        ):
            raise _error("runtime_canary_sandbox_invalid")
        sections[current].append(line)
    if set(sections) != {"Unit", "Service"}:
        raise _error("runtime_canary_sandbox_invalid")
    return {name: tuple(values) for name, values in sections.items()}


def _canary_path_text(path: Path) -> str:
    value = os.fspath(path) if isinstance(path, Path) else ""
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or not value
        or any(
            character
            not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/._-"
            for character in value
        )
    ):
        raise _error("runtime_canary_sandbox_invalid")
    return value


def _canary_unit_binding(
    *, image: _CanaryImage, home: Path, nonce: str
) -> _CanaryUnitBinding:
    """Transform only the typed paths in the exact attested hourly sandbox."""

    if (
        not isinstance(image, _CanaryImage)
        or not isinstance(nonce, str)
        or len(nonce) != 32
        or any(character not in "0123456789abcdef" for character in nonce)
    ):
        raise _error("runtime_canary_sandbox_invalid")
    invocation = _canary_path_text(image.invocation_root)
    release = _canary_path_text(image.release_root)
    state = _canary_path_text(image.state_root)
    home_text = _canary_path_text(home)
    try:
        image.release_root.relative_to(image.invocation_root)
        image.state_root.relative_to(image.invocation_root)
    except ValueError as exc:
        raise _error("runtime_canary_sandbox_invalid") from exc
    if (
        image.release_root == image.state_root
        or release == invocation
        or state == invocation
        or len(image.generation) != 40
        or any(character not in "0123456789abcdef" for character in image.generation)
        or len(image.manifest_digest) != 71
        or not image.manifest_digest.startswith("sha256:")
        or any(
            character not in "0123456789abcdef"
            for character in image.manifest_digest.removeprefix("sha256:")
        )
    ):
        raise _error("runtime_canary_sandbox_invalid")
    directives = _unit_directives(image.service)
    expected_exec = (
        "ExecStart=%h/.local/lib/the-hive-runtime/generations/"
        f"{image.generation}/bin/the-hive-hive-hourly-probe "
        "%h/.local/lib/the-hive-runtime "
        f"{image.generation} {image.manifest_digest} "
        f"{_HOURLY_PROBE_PROTECTED_HOME_RUNTIME_ARGUMENT} --json"
    )
    if directives.get("Unit") != (
        "Description=The Hive Hive hourly self-test",
        "Documentation=man:systemd.service(5)",
    ):
        raise _error("runtime_canary_sandbox_invalid")
    unit_stem = _CANARY_UNIT_PREFIX + nonce
    canonical_release = Path(home_text) / ".local" / "lib" / "the-hive-runtime"
    canonical_state = Path(home_text) / ".local" / "state" / "codex-master-mcp"
    canonical_release_text = _canary_path_text(canonical_release)
    canonical_state_text = _canary_path_text(canonical_state)
    replacements = {
        _HOURLY_PROBE_MANAGED_RUNTIME_DIRECTORY: f"RuntimeDirectory={unit_stem}",
        _HOURLY_PROBE_MANAGED_RUNTIME_DIRECTORY_MODE: (
            _HOURLY_PROBE_MANAGED_RUNTIME_DIRECTORY_MODE
        ),
        _HOURLY_PROBE_RUNTIME_ROOT_BINDING: (
            f"BindReadOnlyPaths={release}:{canonical_release_text}:norbind"
        ),
        _HOURLY_PROBE_PROTECTED_HOME_RUNTIME_BINDING: (
            _HOURLY_PROBE_PROTECTED_HOME_RUNTIME_BINDING
        ),
        _HOURLY_PROBE_STATE_BINDING: (
            f"BindPaths={state}:{canonical_state_text}:norbind"
        ),
        _HOURLY_PROBE_STATE_WRITE_PATH: f"ReadWritePaths={canonical_state_text}",
    }
    special_keys = {
        "RuntimeDirectory",
        "RuntimeDirectoryMode",
        "BindReadOnlyPaths",
        "BindPaths",
        "ReadWritePaths",
    }
    properties: list[str] = ["Documentation=man:systemd.service(5)"]
    seen: set[str] = set()
    type_seen = False
    exec_seen = False
    for directive in directives["Service"]:
        key = directive.partition("=")[0]
        if key == "Type":
            if type_seen or directive != "Type=oneshot":
                raise _error("runtime_canary_sandbox_invalid")
            type_seen = True
        elif key == "ExecStart":
            if exec_seen or directive != expected_exec:
                raise _error("runtime_canary_sandbox_invalid")
            exec_seen = True
        elif key in special_keys:
            replacement = replacements.get(directive)
            if replacement is None or directive in seen:
                raise _error("runtime_canary_sandbox_invalid")
            seen.add(directive)
            properties.append(replacement)
            if directive == _HOURLY_PROBE_MANAGED_RUNTIME_DIRECTORY:
                properties.append(
                    "BindReadOnlyPaths="
                    f"%t/{unit_stem}:%t/the-hive-hourly-runtime:norbind"
                )
        else:
            properties.append(directive)
    if not type_seen or not exec_seen or seen != set(replacements):
        raise _error("runtime_canary_sandbox_invalid")
    properties.extend(("RemainAfterExit=yes", "StandardOutput=null", "StandardError=null"))
    return _CanaryUnitBinding(
        name=f"{unit_stem}.service",
        description=f"The Hive runtime canary {nonce}",
        home=home,
        properties=tuple(properties),
        command=(
            os.fspath(
                canonical_release
                / "generations"
                / image.generation
                / "bin"
                / "the-hive-hive-hourly-probe"
            ),
            canonical_release_text,
            image.generation,
            image.manifest_digest,
            _HOURLY_PROBE_PROTECTED_HOME_RUNTIME_ARGUMENT,
            "--json",
        ),
    )


def _bind_cutover_inputs(home: Path) -> _BoundCutover:
    """Bind exactly the source, pre-runtime and unit state before mutation."""

    release_root, units, state_root, legacy_launcher = _home_paths(home)
    pricing_launcher = home / ".local" / "bin" / _PRICING_LAUNCHER
    pricing_units = tuple(units / name for name in _PRICING_UNITS)
    try:
        home_info = home.lstat()
    except OSError as exc:
        raise _error("runtime_lifecycle_home_invalid") from exc
    if (
        stat.S_ISLNK(home_info.st_mode)
        or not stat.S_ISDIR(home_info.st_mode)
        or home_info.st_uid != os.geteuid()
        or stat.S_IMODE(home_info.st_mode) & 0o022
    ):
        raise _error("runtime_lifecycle_home_invalid")
    for path in (
        release_root,
        units,
        state_root,
        legacy_launcher,
        pricing_launcher,
        *pricing_units,
    ):
        _bound_path_from_home(home, path)
    repository = Path(__file__).resolve().parents[2]
    sources = (
        repository / "scripts" / "the-hive-hive-hourly-probe-install",
        repository / "src" / "the_hive" / "usage_snapshot.py",
        repository / "src" / "the_hive" / "limit_tracker.py",
        repository / "src" / "the_hive" / "runtime_lifecycle.py",
    )
    source_digests = tuple((path, _source_digest(path)) for path in sources)
    source_commit, source_tree_digest = _source_tree_binding(repository)
    generations = release_root / "generations"
    try:
        generations_before = frozenset(item.name for item in generations.iterdir())
    except FileNotFoundError:
        generations_before = frozenset()
    except OSError as exc:
        raise _error("runtime_lifecycle_binding_invalid") from exc
    if any(
        not name or "/" in name or name in {".", ".."} for name in generations_before
    ):
        raise _error("runtime_lifecycle_binding_invalid")
    files = (
        (
            release_root / ".the-hive-release-pointers.json",
            _regular_bytes(
                release_root / ".the-hive-release-pointers.json",
                maximum=_MAX_HEALTH_BYTES,
                mode=0o644,
            ),
            0o644,
        ),
        (
            release_root / "the-hive-mcp",
            _regular_bytes(
                release_root / "the-hive-mcp", maximum=_MAX_UNIT_BYTES, mode=0o755
            ),
            0o755,
        ),
        (
            legacy_launcher,
            _regular_bytes(legacy_launcher, maximum=_MAX_UNIT_BYTES, mode=0o755),
            0o755,
        ),
        (
            pricing_launcher,
            _regular_bytes(pricing_launcher, maximum=_MAX_UNIT_BYTES, mode=0o755),
            0o755,
        ),
        (
            state_root / _OBSERVATION_NAME,
            _regular_bytes(
                state_root / _OBSERVATION_NAME,
                maximum=_MAX_OBSERVATION_BYTES,
                mode=0o600,
            ),
            0o600,
        ),
        *(
            (units / name, _unit_bytes(units, name), 0o644)
            for name in (_NEW_SERVICE, _NEW_TIMER, _LEGACY_SERVICE, _LEGACY_TIMER)
        ),
        *((path, _unit_bytes(units, path.name), 0o644) for path in pricing_units),
    )
    return _BoundCutover(
        home=home,
        release_root=release_root,
        units=units,
        state_root=state_root,
        files=files,
        source_digests=source_digests,
        source_commit=source_commit,
        generations_before=generations_before,
        legacy_present=any(
            value is not None
            for path, value, _mode in files
            if path.name in {_LEGACY_SERVICE, _LEGACY_TIMER}
        ),
        states=(),
        source_tree_digest=source_tree_digest,
    )


def _revalidate_cutover_inputs(bound: _BoundCutover) -> None:
    for path in (bound.release_root, bound.units, bound.state_root):
        _bound_path_from_home(bound.home, path)
    for path, digest in bound.source_digests:
        if _source_digest(path) != digest:
            raise _error("runtime_lifecycle_source_changed")
    if bound.source_tree_digest:
        repository = Path(__file__).resolve().parents[2]
        commit, tree_digest = _source_tree_binding(repository)
        if commit != bound.source_commit or tree_digest != bound.source_tree_digest:
            raise _error("runtime_lifecycle_source_changed")
    for path, content, mode in bound.files:
        maximum = (
            _MAX_HEALTH_BYTES
            if path.name == ".the-hive-release-pointers.json"
            else (
                _MAX_OBSERVATION_BYTES
                if path.name == _OBSERVATION_NAME
                else _MAX_UNIT_BYTES
            )
        )
        if _regular_bytes(path, maximum=maximum, mode=mode) != content:
            raise _error("runtime_lifecycle_input_changed")


def _bind_systemd_states(bound: _BoundCutover, systemctl: Systemctl) -> _BoundCutover:
    """Bind manager state before the installer changes either unit namespace."""

    states = tuple(
        (unit, _show(systemctl, unit))
        for unit in (_NEW_SERVICE, _NEW_TIMER, _LEGACY_SERVICE, _LEGACY_TIMER)
    )
    bound_states = dict(states)
    if any(not _valid_bound_unit_state(state) for state in bound_states.values()):
        raise _error("runtime_lifecycle_systemd_state_invalid")
    if (
        (
            _state_is_enabled(bound_states[_NEW_TIMER])
            and _state_is_enabled(bound_states[_LEGACY_TIMER])
        )
        or (
            _state_is_active(bound_states[_NEW_TIMER])
            and _state_is_active(bound_states[_LEGACY_TIMER])
        )
        or (
            _state_is_active(bound_states[_NEW_SERVICE])
            and _state_is_active(bound_states[_LEGACY_SERVICE])
        )
    ):
        raise _error("runtime_lifecycle_duplicate_preexisting")
    return replace(bound, states=states)


def _install_attested_runtime(home: Path) -> None:
    """Cross the existing attested-installer boundary; never compose a wrapper."""

    repository = Path(__file__).resolve().parents[2]
    try:
        _source_tree_binding(repository)
        with _bound_installer_entry(repository) as entry:
            installer = runpy.run_path(f"/proc/self/fd/{entry.descriptor}")
            install = installer.get("_install_attested_runtime")
            if not callable(install):
                raise _error("runtime_lifecycle_installer_invalid")
            result = install(home=home)
    except RuntimeLifecycleError:
        raise
    except Exception as exc:
        raise _error("runtime_lifecycle_install_failed") from exc
    if not isinstance(result, Mapping) or result.get("status") != "installed":
        raise _error("runtime_lifecycle_install_failed")


def _bind_post_install(home: Path) -> _PostInstallBinding:
    """Attest the newly published image and exact new unit pair before use."""

    release_root, units, _state_root, _launcher = _home_paths(home)
    for path in (release_root, units):
        _bound_path_from_home(home, path)
    identity = _runtime_identity(release_root)
    if identity is None or identity.get("consumer_pin") is not True:
        raise _error("runtime_lifecycle_postinstall_invalid")
    generation = identity.get("generation")
    manifest_digest = identity.get("manifest_digest")
    if not isinstance(generation, str) or not isinstance(manifest_digest, str):
        raise _error("runtime_lifecycle_postinstall_invalid")
    service, timer = _attested_hourly_unit_bytes(
        release_root=release_root,
        generation=generation,
        manifest_digest=manifest_digest,
    )
    installed_service = _unit_bytes(units, _NEW_SERVICE)
    installed_timer = _unit_bytes(units, _NEW_TIMER)
    if installed_service != service or installed_timer != timer:
        raise _error("runtime_lifecycle_postinstall_invalid")
    return _PostInstallBinding(
        identity=(generation, manifest_digest),
        service=service,
        timer=timer,
    )


def _revalidate_post_install(bound: _PostInstallBinding, home: Path) -> None:
    if _bind_post_install(home) != bound:
        raise _error("runtime_lifecycle_postinstall_changed")


def _attested_hourly_unit_bytes(
    *, release_root: Path, generation: str, manifest_digest: str
) -> tuple[bytes, bytes]:
    """Render the installed pair only from the current manifest-attested image."""

    try:
        from the_hive.runtime_layout import RuntimeLayout

        layout = RuntimeLayout.from_current_release(
            release_root, generation, manifest_digest
        )
        service_template = layout.read_attested_file(
            "systemd/user/the-hive-hive-hourly-probe.service"
        )
        timer = layout.read_attested_file(
            "systemd/user/the-hive-hive-hourly-probe.timer"
        )
        template = service_template.decode("utf-8")
    except (RuntimeLifecycleError, UnicodeDecodeError, ValueError) as exc:
        raise _error("runtime_lifecycle_postinstall_invalid") from exc
    template_lines = template.splitlines()
    if (
        template.count("@MASTERJET_GENERATION@") != 2
        or template.count("@MASTERJET_MANIFEST_DIGEST@") != 1
        or [line for line in template_lines if line.startswith("PrivateTmp=")]
        != ["PrivateTmp=yes"]
        or [line for line in template_lines if line.startswith("ProtectHome=")]
        != ["ProtectHome=tmpfs"]
        or [line for line in template_lines if line.startswith("RuntimeDirectory=")]
        != [_HOURLY_PROBE_MANAGED_RUNTIME_DIRECTORY]
        or [line for line in template_lines if line.startswith("RuntimeDirectoryMode=")]
        != [_HOURLY_PROBE_MANAGED_RUNTIME_DIRECTORY_MODE]
        or [line for line in template_lines if line.startswith("BindReadOnlyPaths=")]
        != [
            _HOURLY_PROBE_RUNTIME_ROOT_BINDING,
            _HOURLY_PROBE_PROTECTED_HOME_RUNTIME_BINDING,
        ]
        or [line for line in template_lines if line.startswith("BindPaths=")]
        != [_HOURLY_PROBE_STATE_BINDING]
        or [line for line in template_lines if line.startswith("ReadWritePaths=")]
        != [_HOURLY_PROBE_STATE_WRITE_PATH]
    ):
        raise _error("runtime_lifecycle_postinstall_invalid")
    service = (
        template.replace("@MASTERJET_GENERATION@", generation)
        .replace("@MASTERJET_MANIFEST_DIGEST@", manifest_digest)
        .encode("utf-8")
    )
    expected = (
        "ExecStart=%h/.local/lib/the-hive-runtime/generations/"
        f"{generation}/bin/the-hive-hive-hourly-probe "
        "%h/.local/lib/the-hive-runtime "
        f"{generation} {manifest_digest} "
        f"{_HOURLY_PROBE_PROTECTED_HOME_RUNTIME_ARGUMENT} --json"
    )
    terms = [
        line.strip()
        for line in timer.decode("utf-8", errors="replace").splitlines()
        if line.strip().startswith("OnCalendar=")
    ]
    if (
        "@MASTERJET_" in service.decode("utf-8")
        or [
            line
            for line in service.decode("utf-8").splitlines()
            if line.startswith("ExecStart=")
        ]
        != [expected]
        or terms != [_EIGHT_UTC_TERMS]
    ):
        raise _error("runtime_lifecycle_postinstall_invalid")
    return service, timer


def _systemctl_mutate(systemctl: Systemctl, arguments: tuple[str, ...]) -> None:
    try:
        result = systemctl(arguments)
    except RuntimeLifecycleError:
        raise
    except Exception as exc:
        raise _error("runtime_lifecycle_systemd_failed") from exc
    if not isinstance(result, Mapping) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in result.items()
    ):
        raise _error("runtime_lifecycle_systemd_invalid")


def _cutover_systemctl_mutate(
    systemctl: Systemctl, arguments: tuple[str, ...], *, phase: str
) -> None:
    """Run one named cutover mutation without exposing manager error detail."""

    try:
        _systemctl_mutate(systemctl, arguments)
    except RuntimeLifecycleError as exc:
        raise _CutoverMutationError(phase=phase, error=exc) from exc


def _atomic_restore(path: Path, content: bytes, mode: int) -> None:
    descriptor = -1
    temporary = Path()
    try:
        descriptor, name = tempfile.mkstemp(
            prefix=f".{path.name}.rollback.", dir=path.parent
        )
        temporary = Path(name)
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(
            path.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        temporary = Path()
    except OSError as exc:
        raise _error("runtime_lifecycle_rollback_failed") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary != Path():
            try:
                temporary.unlink()
            except OSError:
                pass


def _remove_legacy_hourly_units(bound: _BoundCutover) -> None:
    for path, previous, mode in bound.files:
        if path.name not in {_LEGACY_SERVICE, _LEGACY_TIMER}:
            continue
        current = _regular_bytes(path, maximum=_MAX_UNIT_BYTES, mode=mode)
        if current != previous:
            raise _error("runtime_lifecycle_input_changed")
        if current is not None:
            try:
                path.unlink()
            except OSError as exc:
                raise _error("runtime_lifecycle_unit_remove_failed") from exc


def _legacy_requires_migration(bound: _BoundCutover) -> bool:
    states = dict(bound.states)
    return (
        bound.legacy_present
        or _state_is_enabled(states.get(_LEGACY_TIMER, {}))
        or _state_is_active(states.get(_LEGACY_TIMER, {}))
        or _state_is_active(states.get(_LEGACY_SERVICE, {}))
    )


def _revalidate_legacy_units(bound: _BoundCutover) -> None:
    """Keep each old-unit manager action bound to the exact pre-cutover pair."""

    _bound_path_from_home(bound.home, bound.units)
    for path, content, mode in bound.files:
        if path.name not in {_LEGACY_SERVICE, _LEGACY_TIMER}:
            continue
        if _regular_bytes(path, maximum=_MAX_UNIT_BYTES, mode=mode) != content:
            raise _error("runtime_lifecycle_legacy_changed")


def _discard_new_generation(bound: _BoundCutover) -> None:
    """Discard only this transaction's newly attested, unreferenced generation."""

    if bound.source_commit in bound.generations_before:
        return
    candidate = bound.release_root / "generations" / bound.source_commit
    try:
        from the_hive.runtime_layout import RuntimeLayout

        layout = RuntimeLayout.from_runtime_root(candidate)
        raw = _regular_bytes(
            candidate / ".the-hive-runtime-manifest.json",
            maximum=_MAX_HEALTH_BYTES,
            mode=0o644,
        )
        manifest = json.loads(raw.decode("utf-8")) if raw is not None else None
        if (
            layout.root != candidate
            or not isinstance(manifest, dict)
            or manifest.get("generation") != bound.source_commit
            or manifest.get("commit") != bound.source_commit
        ):
            raise _error("runtime_lifecycle_rollback_failed")
        shutil.rmtree(candidate)
    except RuntimeLifecycleError:
        raise
    except (OSError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _error("runtime_lifecycle_rollback_failed") from exc


def _restore_bound_state_result(
    bound: _BoundCutover, systemctl: Systemctl
) -> _RollbackResult:
    """Restore the bound transaction state with fixed, public-safe diagnostics."""

    try:
        for path, content, mode in bound.files:
            maximum = (
                _MAX_HEALTH_BYTES
                if path.name == ".the-hive-release-pointers.json"
                else (
                    _MAX_OBSERVATION_BYTES
                    if path.name == _OBSERVATION_NAME
                    else _MAX_UNIT_BYTES
                )
            )
            current = _regular_bytes(path, maximum=maximum, mode=mode)
            if content is None:
                if current is not None:
                    path.unlink()
            elif current != content:
                _atomic_restore(path, content, mode)
            if _regular_bytes(path, maximum=maximum, mode=mode) != content:
                raise _error("runtime_lifecycle_rollback_failed")
    except (RuntimeLifecycleError, OSError):
        return _RollbackResult(
            False, _ROLLBACK_PHASE_FILE_RESTORE, "file_restore_failed"
        )

    try:
        _discard_new_generation(bound)
    except RuntimeLifecycleError:
        return _RollbackResult(
            False, _ROLLBACK_PHASE_GENERATION_DISCARD, "generation_discard_failed"
        )

    try:
        _systemctl_mutate(systemctl, ("daemon-reload",))
    except RuntimeLifecycleError:
        return _RollbackResult(
            False, _ROLLBACK_PHASE_DAEMON_RELOAD, "manager_action_failed"
        )

    previous = dict(bound.states)
    # Quiesce the newly activated namespace before restoring an old active
    # one, so rollback also never creates a second running probe timer.
    for unit in (_NEW_TIMER, _NEW_SERVICE, _LEGACY_TIMER, _LEGACY_SERVICE):
        try:
            state = previous.get(unit)
            for operation in _restore_operations(unit, state):
                _systemctl_mutate(systemctl, operation)
        except RuntimeLifecycleError:
            return _RollbackResult(
                False, _ROLLBACK_PHASE_ACTIONS[unit], "manager_action_failed"
            )

    for unit, expected in previous.items():
        try:
            actual = _show(systemctl, unit)
            target = _restored_state_target(unit, expected)
        except RuntimeLifecycleError:
            return _RollbackResult(
                False, _ROLLBACK_PHASE_VERIFICATIONS[unit], "unit_verify_failed"
            )
        if not _state_exactly_matches(actual, target):
            return _RollbackResult(
                False, _ROLLBACK_PHASE_VERIFICATIONS[unit], "unit_verify_mismatch"
            )
    return _RollbackResult(True, "complete", "none")


def _restore_bound_state(bound: _BoundCutover, systemctl: Systemctl) -> bool:
    """Compatibility predicate for internal callers needing only restoration."""

    return _restore_bound_state_result(bound, systemctl).restored


def _rollback_failure_result(
    *, status: str, rollback: _RollbackResult
) -> dict[str, object]:
    """Return only fixed rollback telemetry, never exception or command data."""

    if (
        rollback.restored
        or rollback.phase not in _ROLLBACK_FAILURE_PHASES
        or rollback.error_code not in _ROLLBACK_FAILURE_CODES
    ):
        return {
            "status": status,
            "raw_output": "not_returned",
            "rollback_phase": "telemetry_invalid",
            "rollback_error": "telemetry_invalid",
        }
    return {
        "status": status,
        "raw_output": "not_returned",
        "rollback_phase": rollback.phase,
        "rollback_error": rollback.error_code,
    }


def _cutover_mutation_failure_result(
    failure: _CutoverMutationError,
) -> dict[str, object]:
    """Publish only the fixed phase/error pair after a complete rollback."""

    if (
        failure.phase not in _CUTOVER_MUTATION_PHASES
        or not failure.status_whitelisted
    ):
        phase = _CUTOVER_TELEMETRY_INVALID
        error = _CUTOVER_TELEMETRY_INVALID
    else:
        phase = failure.phase
        error = _CUTOVER_MUTATION_ERROR
    return {
        "status": str(failure),
        "raw_output": "not_returned",
        "failure_phase": phase,
        "failure_error": error,
    }


def _publish_rollback_failure(bound: _BoundCutover) -> bool:
    """Best-effort only after rollback loss: publish the canonical red Hive alarm.

    The transaction never continues on an alarm publication error; its returned
    stable failure code remains fail closed.  A malformed runtime cannot be
    allowed to select an arbitrary queen, so the probe API receives ``None``
    when the currently bound release no longer attests.
    """

    layout = None
    try:
        from the_hive.runtime_layout import RuntimeLayout

        raw = _regular_bytes(
            bound.release_root / ".the-hive-release-pointers.json",
            maximum=_MAX_HEALTH_BYTES,
            mode=0o644,
        )
        if raw is not None:
            pointer = json.loads(raw.decode("utf-8"))
            current = pointer.get("current") if isinstance(pointer, dict) else None
            if isinstance(current, dict):
                generation = current.get("generation")
                digest = current.get("manifest_digest")
                if isinstance(generation, str) and isinstance(digest, str):
                    layout = RuntimeLayout.from_current_release(
                        bound.release_root, generation, digest
                    )
    except (
        RuntimeLifecycleError,
        ValueError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ):
        layout = None
    try:
        from the_hive.hive.hourly_probe import publish_lifecycle_failure

        publish_lifecycle_failure(
            layout=layout,
            state_directory=bound.state_root,
            reason_code="runtime_lifecycle_rollback_failed",
        )
    except Exception:
        return False
    return True


def _unit_bytes(units: Path, name: str) -> bytes | None:
    return _regular_bytes(units / name, maximum=_MAX_UNIT_BYTES, mode=0o644)


def _systemd_run_failure_code(
    *, returncode: object, stdout: object, stderr: object
) -> str:
    """Classify only exact, installed LANG=C systemd-run failure lines."""

    if (
        returncode != 1
        or stdout != ""
        or not isinstance(stderr, str)
        or len(stderr) > 512
    ):
        return "runtime_canary_manager_failed"
    return _CANARY_SYSTEMD_RUN_FAILURES.get(
        stderr, "runtime_canary_manager_failed"
    )


def _systemd_run_default(arguments: tuple[str, ...]) -> Mapping[str, str]:
    """Create one transient user unit without inheriting the caller environment."""

    runtime_directory = f"/run/user/{os.geteuid()}"
    completed = None
    try:
        completed = subprocess.run(
            [
                "/usr/bin/systemd-run",
                "--user",
                "--no-pager",
                "--quiet",
                *arguments,
            ],
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=_CANARY_MANAGER_START_SECONDS,
            env={
                "LANG": "C",
                "PATH": "/usr/bin:/bin",
                "XDG_RUNTIME_DIR": runtime_directory,
                "DBUS_SESSION_BUS_ADDRESS": f"unix:path={runtime_directory}/bus",
            },
        )
    except (OSError, subprocess.SubprocessError):
        pass
    if completed is None:
        raise _error("runtime_canary_manager_unavailable")
    if completed.returncode != 0:
        raise _error(
            _systemd_run_failure_code(
                returncode=completed.returncode,
                stdout=completed.stdout,
                stderr=completed.stderr,
            )
        )
    return {}


def _systemctl_default(arguments: tuple[str, ...]) -> Mapping[str, str]:
    """Use the same UID's user manager with a bounded, data-sparse protocol."""

    runtime_directory = f"/run/user/{os.geteuid()}"
    try:
        completed = subprocess.run(
            ["/usr/bin/systemctl", "--user", "--no-pager", *arguments],
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=15,
            env={
                "LANG": "C",
                "PATH": "/usr/bin:/bin",
                "XDG_RUNTIME_DIR": runtime_directory,
                "DBUS_SESSION_BUS_ADDRESS": f"unix:path={runtime_directory}/bus",
            },
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise _error("runtime_lifecycle_systemd_unavailable") from exc
    if completed.returncode != 0:
        raise _error("runtime_lifecycle_systemd_failed")
    result: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        key, separator, value = line.partition("=")
        if not separator or not key or len(key) > 64 or len(value) > 256:
            raise _error("runtime_lifecycle_systemd_invalid")
        result[key] = value
    return result


def _show(systemctl: Systemctl, unit: str) -> Mapping[str, str]:
    try:
        result = systemctl(
            (
                "show",
                unit,
                "--property=LoadState,UnitFileState,ActiveState,Result,ExecMainStatus",
            )
        )
    except RuntimeLifecycleError:
        raise
    except Exception as exc:
        raise _error("runtime_lifecycle_systemd_unavailable") from exc
    if not isinstance(result, Mapping) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in result.items()
    ):
        raise _error("runtime_lifecycle_systemd_invalid")
    return result


def _unit_state(systemctl: Systemctl, unit: str) -> Mapping[str, str]:
    try:
        return _show(systemctl, unit)
    except RuntimeLifecycleError as exc:
        return {"error": str(exc)}


def _state_is_enabled(state: Mapping[str, str]) -> bool:
    return state.get("UnitFileState") in {"enabled", "enabled-runtime"}


def _state_is_active(state: Mapping[str, str]) -> bool:
    return state.get("ActiveState") == "active"


def _canary_show(systemctl: Systemctl, unit: str) -> Mapping[str, str]:
    try:
        result = systemctl(("show", unit, _CANARY_SHOW_PROPERTIES))
    except RuntimeLifecycleError:
        raise
    except Exception as exc:
        raise _error("runtime_canary_manager_unavailable") from exc
    required = {
        "LoadState",
        "ActiveState",
        "Description",
        "Transient",
        "Result",
        "ExecMainStatus",
    }
    if (
        not isinstance(result, Mapping)
        or set(result) != required
        or any(
            not isinstance(key, str)
            or not isinstance(value, str)
            or len(value) > 256
            for key, value in result.items()
        )
    ):
        raise _error("runtime_canary_manager_invalid")
    return dict(result)


def _canary_unit_owned(
    state: Mapping[str, str], binding: _CanaryUnitBinding
) -> bool:
    return (
        state.get("LoadState") == "loaded"
        and state.get("Transient") == "yes"
        and state.get("Description") == binding.description
    )


def _start_canary_unit(
    systemd_run: SystemdRun, binding: _CanaryUnitBinding
) -> None:
    try:
        result = systemd_run(binding.run_arguments)
    except RuntimeLifecycleError:
        raise
    except Exception as exc:
        raise _error("runtime_canary_manager_unavailable") from exc
    if not isinstance(result, Mapping) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in result.items()
    ):
        raise _error("runtime_canary_manager_invalid")


def _wait_for_canary_result(
    systemctl: Systemctl, binding: _CanaryUnitBinding
) -> Mapping[str, str]:
    deadline = time.monotonic() + _CANARY_RESULT_SECONDS
    while True:
        state = _canary_show(systemctl, binding.name)
        if not _canary_unit_owned(state, binding):
            raise _error("runtime_canary_unit_identity_invalid")
        active = state.get("ActiveState")
        if active in {"active", "failed"}:
            return state
        if active not in {"inactive", "activating", "deactivating", "reloading"}:
            raise _error("runtime_canary_manager_invalid")
        if time.monotonic() >= deadline:
            raise _error("runtime_canary_timeout")
        time.sleep(0.1)


def _cleanup_canary_unit(
    systemctl: Systemctl,
    binding: _CanaryUnitBinding,
    *,
    ownership_attested: bool,
) -> bool:
    """Quiesce only after current exact ownership; history never authorizes."""

    clean = True
    try:
        state = _canary_show(systemctl, binding.name)
    except RuntimeLifecycleError:
        return False
    if state.get("LoadState") == "not-found":
        return clean
    if not _canary_unit_owned(state, binding):
        return False
    try:
        _systemctl_mutate(systemctl, ("stop", binding.name))
    except RuntimeLifecycleError:
        clean = False
    try:
        after_stop = _canary_show(systemctl, binding.name)
    except RuntimeLifecycleError:
        return False
    if after_stop.get("LoadState") == "not-found":
        return clean
    if not _canary_unit_owned(after_stop, binding):
        return False
    try:
        _systemctl_mutate(systemctl, ("reset-failed", binding.name))
    except RuntimeLifecycleError:
        clean = False
    if not clean:
        try:
            _canary_show(systemctl, binding.name)
        except RuntimeLifecycleError:
            pass
        return False
    deadline = time.monotonic() + _CANARY_CLEANUP_SECONDS
    while True:
        try:
            final = _canary_show(systemctl, binding.name)
        except RuntimeLifecycleError:
            return False
        if final.get("LoadState") == "not-found":
            return clean
        if not _canary_unit_owned(final, binding):
            return False
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)


def _canary_diagnostic_value(value: object, *, command_ready: bool) -> str:
    if not isinstance(value, Mapping):
        raise _error("runtime_canary_evidence_invalid")
    code = value.get("code")
    expected = {
        "code": "ok" if command_ready else code,
        "exit_code": 0 if command_ready else None,
        "stderr": {
            "state": "empty" if command_ready else "not_returned",
            "excerpt": "",
            "redaction_applied": False,
        },
    }
    if value != expected or (
        command_ready and code != "ok"
    ) or (not command_ready and code not in _CANARY_STAGE_CODES):
        raise _error("runtime_canary_evidence_invalid")
    return code


def _canary_evidence_result(
    *, image: _CanaryImage, manager_state: Mapping[str, str]
) -> tuple[str, str | None]:
    """Return only one fixed diagnosis from the private Canary state."""

    try:
        raw = _regular_bytes(
            image.state_root / "hive-hourly-health.json",
            maximum=_CANARY_HEALTH_BYTES,
            mode=0o600,
        )
    except RuntimeLifecycleError as exc:
        raise _error("runtime_canary_evidence_invalid") from exc
    if raw is None:
        raise _error("runtime_canary_evidence_invalid")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise _error("runtime_canary_evidence_invalid") from exc
    if not isinstance(payload, Mapping) or set(payload) != {
        "schema_version",
        "checked_at",
        "checks",
        "commands",
        "diagnostics",
        "alarm",
        "global_pilot_readiness",
    }:
        raise _error("runtime_canary_evidence_invalid")
    checks = payload.get("checks")
    commands = payload.get("commands")
    diagnostics = payload.get("diagnostics")
    keys = {"runtime_status", "hive_status", "hive_doctor"}
    if (
        payload.get("schema_version") != 3
        or not isinstance(payload.get("checked_at"), str)
        or not isinstance(checks, Mapping)
        or set(checks) != {"runtime_layout", "hive_runtime", "hive_doctor"}
        or any(type(value) is not bool for value in checks.values())
        or not isinstance(commands, Mapping)
        or set(commands) != keys
        or any(type(value) is not bool for value in commands.values())
        or not isinstance(diagnostics, Mapping)
        or set(diagnostics) != keys
    ):
        raise _error("runtime_canary_evidence_invalid")
    codes = {
        _canary_diagnostic_value(
            diagnostics[name], command_ready=commands[name] is True
        )
        for name in keys
    }
    if (
        all(checks.values())
        and all(commands.values())
        and codes == {"ok"}
        and manager_state.get("ActiveState") == "active"
        and manager_state.get("Result") == "success"
        and manager_state.get("ExecMainStatus") == "0"
    ):
        return "runtime_canary_green", None
    stage_codes = codes & _CANARY_STAGE_CODES
    if (
        len(stage_codes) == 1
        and manager_state.get("ActiveState") == "failed"
        and manager_state.get("Result") == "exit-code"
        and manager_state.get("ExecMainStatus") == "1"
    ):
        return "runtime_canary_red", next(iter(stage_codes))
    raise _error("runtime_canary_evidence_invalid")


def _valid_bound_unit_state(state: Mapping[str, str]) -> bool:
    """Accept only states for which rollback has a defined, safe operation."""

    load = state.get("LoadState")
    unit_file = state.get("UnitFileState")
    active = state.get("ActiveState")
    if load == "not-found":
        return unit_file == "disabled" and active == "inactive"
    return (
        load == "loaded"
        and unit_file
        in {"enabled", "enabled-runtime", "disabled", "masked", "static", "indirect"}
        and active in {"active", "inactive", "failed"}
    )


def _restore_operations(
    unit: str, state: Mapping[str, str] | None
) -> tuple[tuple[str, ...], ...]:
    """Return the complete, ordered manager inverse for one bound unit.

    Every service not bound as active may have acquired a failed record while
    the cutover candidate was running. It must therefore be quiesced before
    that record is reset; both operations remain under the caller's one
    fail-closed phase boundary.
    """

    if state is None:
        return ()
    if not _valid_bound_unit_state(state):
        raise _error("runtime_lifecycle_systemd_state_invalid")
    if state.get("LoadState") == "not-found":
        return ()
    if unit.endswith(".timer"):
        return (
            (
                ("enable", "--now", unit)
                if _state_is_enabled(state)
                else ("disable", "--now", unit)
            ),
        )
    if unit.endswith(".service") and not _state_is_active(state):
        return (("stop", unit), ("reset-failed", unit))
    return (("start", unit),) if _state_is_active(state) else (("stop", unit),)


def _restored_state_target(
    unit: str, state: Mapping[str, str]
) -> Mapping[str, str]:
    """Name the exact manager state a safe inverse operation can recreate.

    systemd has no non-executing operation that recreates a historical
    ``failed`` service state. Its safe inverse first quiesces the service and
    then resets that historical record, whose durable contract is the same
    loaded/unit-file state with the service quiescent. This normalization is
    deliberately limited to services that were already failed before cutover;
    timers and every other state remain exact.
    """

    if unit.endswith(".service") and state.get("ActiveState") == "failed":
        return {**state, "ActiveState": "inactive"}
    return state


def _state_exactly_matches(
    actual: Mapping[str, str], expected: Mapping[str, str]
) -> bool:
    return all(
        actual.get(key) == expected.get(key)
        for key in ("LoadState", "UnitFileState", "ActiveState")
    )


def _parse_health(state_root: Path) -> tuple[bool, bool]:
    """Return (health-v3-green, queen-alarm-cleared) without repairing anything."""

    try:
        raw = _regular_bytes(
            state_root / "hive-hourly-health.json",
            maximum=_MAX_HEALTH_BYTES,
            mode=0o600,
        )
        if raw is None:
            return False, False
        value = json.loads(raw.decode("utf-8"))
    except (RuntimeLifecycleError, UnicodeDecodeError, json.JSONDecodeError):
        return False, False
    if not isinstance(value, dict) or value.get("schema_version") != 3:
        return False, False
    checks = value.get("checks")
    alarm = value.get("alarm")
    health = isinstance(checks, dict) and checks == {
        "runtime_layout": True,
        "hive_runtime": True,
        "hive_doctor": True,
    }
    cleared = (
        isinstance(alarm, dict)
        and alarm.get("scope") == "hive"
        and alarm.get("status") == "cleared"
        and alarm.get("reason_codes") == []
    )
    return health, cleared


def _runtime_identity(release_root: Path) -> dict[str, object] | None:
    try:
        from the_hive.runtime_layout import RuntimeLayout

        raw = _regular_bytes(
            release_root / ".the-hive-release-pointers.json",
            maximum=_MAX_HEALTH_BYTES,
            mode=0o644,
        )
        if raw is None:
            return None
        pointer = json.loads(raw.decode("utf-8"))
        if not isinstance(pointer, dict) or not isinstance(
            pointer.get("current"), dict
        ):
            return None
        current = pointer["current"]
        generation, digest = current.get("generation"), current.get("manifest_digest")
        if not isinstance(generation, str) or not isinstance(digest, str):
            return None
        layout = RuntimeLayout.from_current_release(release_root, generation, digest)
        consumer = layout.read_attested_file("src/the_hive/usage_snapshot.py")
        pin = _consumer_producer_contract(consumer)
        return {
            "generation": generation,
            "manifest_digest": digest,
            "consumer_pin": pin,
        }
    except (
        RuntimeLifecycleError,
        ValueError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ):
        return None


def _consumer_producer_contract(raw: bytes) -> bool:
    """Parse named consumer constants from the attested Runtime Image source."""

    try:
        module = ast.parse(raw.decode("utf-8"), mode="exec")
    except (SyntaxError, UnicodeDecodeError):
        return False
    values: dict[str, str] = {}
    for statement in module.body:
        if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
            continue
        target = statement.targets[0]
        value = statement.value
        if (
            isinstance(target, ast.Name)
            and target.id in _PRODUCER_CONSUMER_CONTRACT
            and isinstance(value, ast.Constant)
            and isinstance(value.value, str)
        ):
            values[target.id] = value.value
    python_directory_contract = any(
        isinstance(node, ast.Compare)
        and len(node.ops) == len(node.comparators) == 1
        and isinstance(node.ops[0], ast.NotEq)
        and isinstance(node.comparators[0], ast.Constant)
        and node.comparators[0].value == "python3.14"
        and isinstance(node.left, ast.Subscript)
        and isinstance(node.left.value, ast.Name)
        and node.left.value.id == "python_directory"
        and isinstance(node.left.slice, ast.Constant)
        and node.left.slice.value == 2
        for node in ast.walk(module)
    )
    return values == _PRODUCER_CONSUMER_CONTRACT and python_directory_contract


def _probe_observation_binding(
    *, home: Path, release_root: Path, identity: Mapping[str, object]
) -> _ProbeObservationBinding:
    """Bind the installed zero-argument launcher to its current image pair."""

    generation = identity.get("generation")
    manifest_digest = identity.get("manifest_digest")
    if (
        not isinstance(generation, str)
        or len(generation) != 40
        or any(character not in "0123456789abcdef" for character in generation)
        or not isinstance(manifest_digest, str)
        or not manifest_digest.startswith("sha256:")
        or len(manifest_digest) != 71
    ):
        raise _error("runtime_lifecycle_probe_binding_invalid")
    _release_root, _units, _state_root, launcher = _home_paths(home)
    _bound_path_from_home(home, launcher)
    launcher_bytes = _regular_bytes(launcher, maximum=_MAX_UNIT_BYTES, mode=0o755)
    if launcher_bytes is None:
        raise _error("runtime_lifecycle_probe_binding_invalid")
    try:
        from the_hive.runtime_layout import RuntimeLayout

        layout = RuntimeLayout.from_current_release(
            release_root, generation, manifest_digest
        )
    except (ValueError, RuntimeLifecycleError) as exc:
        raise _error("runtime_lifecycle_probe_binding_invalid") from exc
    return _ProbeObservationBinding(
        generation=generation,
        manifest_digest=manifest_digest,
        launcher_sha256=hashlib.sha256(launcher_bytes).hexdigest(),
        launcher=launcher,
        runtime_layout=layout,
    )


def _observation_payload(
    binding: _ProbeObservationBinding, *, observed_at: datetime
) -> bytes:
    return (
        json.dumps(
            {
                "generation": binding.generation,
                "launcher_sha256": binding.launcher_sha256,
                "manifest_digest": binding.manifest_digest,
                "observed_at": observed_at.astimezone(UTC)
                .isoformat()
                .replace("+00:00", "Z"),
                "returncode": 0,
                "schema_version": 1,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _write_observation(state_root: Path, binding: _ProbeObservationBinding) -> None:
    """Atomically record only a successful bounded launcher invocation."""

    _regular_bytes(
        state_root / _OBSERVATION_NAME,
        maximum=_MAX_OBSERVATION_BYTES,
        mode=0o600,
    )
    _atomic_restore(
        state_root / _OBSERVATION_NAME,
        _observation_payload(binding, observed_at=datetime.now(UTC)),
        0o600,
    )


def _observation_matches(
    *, home: Path, state_root: Path, identity: Mapping[str, object] | None
) -> bool:
    """Read one exact receipt; never infer observation from other health data."""

    if identity is None:
        return False
    try:
        binding = _probe_observation_binding(
            home=home,
            release_root=_home_paths(home)[0],
            identity=identity,
        )
        raw = _regular_bytes(
            state_root / _OBSERVATION_NAME,
            maximum=_MAX_OBSERVATION_BYTES,
            mode=0o600,
        )
        if raw is None:
            return False
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict) or set(value) != {
            "schema_version",
            "generation",
            "manifest_digest",
            "launcher_sha256",
            "observed_at",
            "returncode",
        }:
            return False
        observed_at = value.get("observed_at")
        if not isinstance(observed_at, str) or not observed_at.endswith("Z"):
            return False
        parsed = datetime.fromisoformat(observed_at.removesuffix("Z") + "+00:00")
        age = (datetime.now(UTC) - parsed).total_seconds()
        return (
            value.get("schema_version") == 1
            and value.get("generation") == binding.generation
            and value.get("manifest_digest") == binding.manifest_digest
            and value.get("launcher_sha256") == binding.launcher_sha256
            and value.get("returncode") == 0
            and 0 <= age <= 4 * 60 * 60
        )
    except (
        RuntimeLifecycleError,
        UnicodeDecodeError,
        ValueError,
        json.JSONDecodeError,
    ):
        return False


def _observe_argumentless_installed_probe(home: Path) -> None:
    """Run exactly the installed launcher with no arguments, then bind its receipt."""

    release_root, _units, state_root, _launcher = _home_paths(home)
    identity = _runtime_identity(release_root)
    if identity is None or identity.get("consumer_pin") is not True:
        raise _error("runtime_lifecycle_probe_binding_invalid")
    binding = _probe_observation_binding(
        home=home, release_root=release_root, identity=identity
    )
    try:
        result = run_bounded(
            (os.fspath(binding.launcher),),
            cwd=home,
            home=home,
            timeout_seconds=_PROBE_OBSERVATION_SECONDS,
            stdout_limit=_PROBE_OUTPUT_BYTES,
            stderr_limit=_PROBE_OUTPUT_BYTES,
            runtime_layout=binding.runtime_layout,
        )
    except BoundedProcessError as exc:
        raise _error("runtime_lifecycle_probe_observation_failed") from exc
    if result.returncode != 0:
        raise _error("runtime_lifecycle_probe_failed")
    current = _runtime_identity(release_root)
    if current is None or current.get("consumer_pin") is not True:
        raise _error("runtime_lifecycle_probe_binding_changed")
    rebound = _probe_observation_binding(
        home=home, release_root=release_root, identity=current
    )
    if rebound != binding:
        raise _error("runtime_lifecycle_probe_binding_changed")
    _write_observation(state_root, rebound)


def _d296_and_v2_accepted() -> bool:
    """Ask the independently bound V2 reader for the six fixed owner records."""

    try:
        from the_hive.usage_snapshot import read_usage_evidence_v2

        evidence = read_usage_evidence_v2()
    except Exception:
        return False
    expected = (
        "BW_Nufker",
        "BW_Privat",
        "BW_Work",
        "Birthe_Privat",
        "GPT1",
        "RH_Privat",
    )
    authorities = getattr(evidence, "pool_authorities", ())
    if getattr(evidence, "status", None) != "complete" or len(authorities) != len(
        expected
    ):
        return False
    observed = [
        (
            getattr(item, "account_id", None),
            getattr(item, "pool_id", None),
            getattr(item, "provider", None),
            getattr(item, "hive_available", None),
            tuple(getattr(item, "allowed_model_families", ())),
            getattr(item, "reasoning_minimum", None),
            getattr(item, "reasoning_maximum", None),
            tuple(getattr(item, "allowed_lifecycles", ())),
            getattr(item, "persistent_leadership_eligible", None),
            getattr(item, "long_running_leadership_eligible", None),
        )
        for item in authorities
    ]
    expected_records = [
        (
            account,
            "openai",
            "openai",
            True,
            ("luna", "sol", "terra"),
            "low",
            "max",
            ("ephemeral", "persistent", "session"),
            True,
            True,
        )
        for account in expected
    ]
    return sorted(observed) == sorted(expected_records)


def _probe_gate_allowed(state_root: Path) -> bool:
    try:
        from the_hive.hive.hourly_probe import read_probe_gate

        return (
            read_probe_gate(state_file=state_root / "hive-hourly-health.json").get(
                "allowed"
            )
            is True
        )
    except Exception:
        return False


def _verify_failure(code: str) -> dict[str, object]:
    """Return one bounded, stable red result without inspecting other paths."""

    return {
        "status": "runtime_lifecycle_red",
        "error_code": code,
        "installed": False,
        "enabled": False,
        "active": False,
        "observed": False,
        "runtime_identity": {
            "generation": None,
            "manifest_digest": None,
            "consumer_pin": False,
        },
        "checks": {
            "runtime_attested": False,
            "unit_files": False,
            "eight_utc_terms": False,
            "no_legacy_or_duplicate_timer": False,
            "v2_generation_and_d296_parity": False,
            "health_v3_green": False,
            "queen_alarm_cleared": False,
            "probe_gate_allowed": False,
            "argumentless_probe_observed": False,
        },
        "raw_output": "not_returned",
    }


def _verify_error_code(
    *, checks: Mapping[str, bool], enabled: bool, active: bool, observed: bool
) -> str | None:
    for check, code in (
        ("runtime_attested", "runtime_lifecycle_consumer_pin_invalid"),
        ("unit_files", "runtime_lifecycle_unit_files_invalid"),
        ("eight_utc_terms", "runtime_lifecycle_timer_terms_invalid"),
        ("no_legacy_or_duplicate_timer", "runtime_lifecycle_legacy_timer_present"),
        ("v2_generation_and_d296_parity", "runtime_lifecycle_v2_parity_invalid"),
        ("health_v3_green", "runtime_lifecycle_health_red"),
        ("queen_alarm_cleared", "runtime_lifecycle_queen_alarm_active"),
        ("probe_gate_allowed", "runtime_lifecycle_probe_gate_red"),
        ("argumentless_probe_observed", "runtime_lifecycle_probe_unobserved"),
    ):
        if checks[check] is not True:
            return code
    if not enabled:
        return "runtime_lifecycle_timer_disabled"
    if not active:
        return "runtime_lifecycle_timer_inactive"
    if not observed:
        return "runtime_lifecycle_probe_unobserved"
    return None


def verify(
    *, home: Path, systemctl: Systemctl = _systemctl_default
) -> dict[str, object]:
    """Read only D298 postconditions; never starts, enables, or repairs a unit."""

    try:
        release_root, units, state_root, _legacy_launcher = _home_paths(home)
        for path in (release_root, units, state_root):
            _bound_path_from_home(home, path)
        service = _unit_bytes(units, _NEW_SERVICE)
        timer = _unit_bytes(units, _NEW_TIMER)
        legacy_service = _unit_bytes(units, _LEGACY_SERVICE)
        legacy_timer = _unit_bytes(units, _LEGACY_TIMER)
        identity = _runtime_identity(release_root)
        if identity is None:
            return _verify_failure("runtime_lifecycle_runtime_identity_invalid")
        generation = identity.get("generation")
        manifest_digest = identity.get("manifest_digest")
        if not isinstance(generation, str) or not isinstance(manifest_digest, str):
            return _verify_failure("runtime_lifecycle_runtime_identity_invalid")
        expected_service, expected_timer = _attested_hourly_unit_bytes(
            release_root=release_root,
            generation=generation,
            manifest_digest=manifest_digest,
        )
        if service != expected_service or timer != expected_timer:
            return _verify_failure("runtime_lifecycle_unit_attestation_invalid")
    except RuntimeLifecycleError as exc:
        code = str(exc)
        if code == "runtime_lifecycle_postinstall_invalid":
            code = "runtime_lifecycle_unit_attestation_invalid"
        return _verify_failure(code)
    timer_state = _unit_state(systemctl, _NEW_TIMER)
    old_timer_state = _unit_state(systemctl, _LEGACY_TIMER)
    old_service_state = _unit_state(systemctl, _LEGACY_SERVICE)
    for state in (timer_state, old_timer_state, old_service_state):
        error = state.get("error")
        if isinstance(error, str):
            return _verify_failure(error)
    runtime = identity.get("consumer_pin") is True
    unit_files = service is not None and timer is not None
    timer_terms = (
        [
            line.strip()
            for line in timer.decode("utf-8", errors="replace").splitlines()
            if line.strip().startswith("OnCalendar=")
        ]
        if timer is not None
        else []
    )
    eight = timer_terms == [_EIGHT_UTC_TERMS]
    no_old = (
        legacy_service is None
        and legacy_timer is None
        and old_timer_state.get("LoadState") in {None, "not-found"}
        and old_service_state.get("LoadState") in {None, "not-found"}
        and not _state_is_enabled(old_timer_state)
        and not _state_is_active(old_timer_state)
        and not _state_is_active(old_service_state)
    )
    health, alarm_cleared = _parse_health(state_root)
    v2 = _d296_and_v2_accepted()
    gate_allowed = _probe_gate_allowed(state_root)
    enabled, active = _state_is_enabled(timer_state), _state_is_active(timer_state)
    observed = _observation_matches(home=home, state_root=state_root, identity=identity)
    checks = {
        "runtime_attested": runtime,
        "unit_files": unit_files,
        "eight_utc_terms": eight,
        "no_legacy_or_duplicate_timer": no_old,
        "v2_generation_and_d296_parity": v2,
        "health_v3_green": health,
        "queen_alarm_cleared": alarm_cleared,
        "probe_gate_allowed": gate_allowed,
        "argumentless_probe_observed": observed,
    }
    all_green = all(checks.values()) and enabled and active and observed
    return {
        "status": "runtime_lifecycle_green" if all_green else "runtime_lifecycle_red",
        "error_code": _verify_error_code(
            checks=checks, enabled=enabled, active=active, observed=observed
        ),
        "installed": runtime and unit_files,
        "enabled": enabled,
        "active": active,
        "observed": observed,
        "runtime_identity": identity
        or {"generation": None, "manifest_digest": None, "consumer_pin": False},
        "checks": checks,
        "raw_output": "not_returned",
    }


def status(
    *, home: Path, systemctl: Systemctl = _systemctl_default
) -> dict[str, object]:
    """Alias with the same read-only data-sparse contract as ``verify``."""

    return verify(home=home, systemctl=systemctl)


def _validate_canary_home(home: Path) -> None:
    if not isinstance(home, Path) or not home.is_absolute():
        raise _error("runtime_canary_home_invalid")
    try:
        item = home.lstat()
    except OSError as exc:
        raise _error("runtime_canary_home_invalid") from exc
    if (
        stat.S_ISLNK(item.st_mode)
        or not stat.S_ISDIR(item.st_mode)
        or item.st_uid != os.geteuid()
        or stat.S_IMODE(item.st_mode) & 0o022
    ):
        raise _error("runtime_canary_home_invalid")
    _canary_path_text(home)


def _canary_runtime_root() -> Path:
    return Path(f"/run/user/{os.geteuid()}") / _CANARY_RUNTIME_ROOT_NAME


@contextmanager
def _canary_lock(root: Path):
    descriptor = -1
    try:
        if not isinstance(root, Path) or not root.is_absolute():
            raise _error("runtime_canary_root_invalid")
        _private_directory(root.parent)
        try:
            root.mkdir(mode=0o700)
        except FileExistsError:
            pass
        except FileNotFoundError:
            raise _error("runtime_canary_root_invalid")
        _private_directory(root)
        descriptor = os.open(
            root / _CANARY_LOCK_NAME,
            os.O_RDWR
            | os.O_CREAT
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        item = os.fstat(descriptor)
        if (
            not stat.S_ISREG(item.st_mode)
            or item.st_nlink != 1
            or item.st_uid != os.geteuid()
            or stat.S_IMODE(item.st_mode) != 0o600
        ):
            raise _error("runtime_canary_root_invalid")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise _error("runtime_canary_busy") from exc
        yield
    except RuntimeLifecycleError:
        raise
    except OSError as exc:
        raise _error("runtime_canary_root_invalid") from exc
    finally:
        if descriptor >= 0:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)


def _remove_canary_invocation(*, root: Path, invocation: Path) -> bool:
    if (
        not isinstance(root, Path)
        or not isinstance(invocation, Path)
        or invocation.parent != root
        or not invocation.name.startswith(_CANARY_RUN_PREFIX)
    ):
        return False
    try:
        item = invocation.lstat()
    except FileNotFoundError:
        return True
    except OSError:
        return False
    if (
        stat.S_ISLNK(item.st_mode)
        or not stat.S_ISDIR(item.st_mode)
        or item.st_uid != os.geteuid()
        or stat.S_IMODE(item.st_mode) != 0o700
    ):
        return False
    try:
        shutil.rmtree(invocation)
        invocation.lstat()
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return False


def _canary_result(
    *,
    status_code: str,
    error_code: str | None,
    generation: str | None,
    manifest_digest: str | None,
) -> dict[str, object]:
    return {
        "status": status_code,
        "error_code": error_code,
        "generation": generation,
        "manifest_digest": manifest_digest,
        "raw_output": "not_returned",
    }


def _canary_public_failure(code: str) -> str:
    mapping = {
        "runtime_lifecycle_source_dirty": "runtime_canary_source_dirty",
        "runtime_lifecycle_source_invalid": "runtime_canary_source_invalid",
        "runtime_lifecycle_source_entry_invalid": "runtime_canary_source_invalid",
        "runtime_lifecycle_source_entry_changed": "runtime_canary_source_changed",
    }
    mapped = mapping.get(code, code)
    allowed = {
        "runtime_canary_busy",
        "runtime_canary_evidence_invalid",
        "runtime_canary_home_invalid",
        "runtime_canary_image_invalid",
        "runtime_canary_manager_contract_invalid",
        "runtime_canary_manager_failed",
        "runtime_canary_manager_invalid",
        "runtime_canary_manager_rejected",
        "runtime_canary_manager_unavailable",
        "runtime_canary_root_invalid",
        "runtime_canary_sandbox_invalid",
        "runtime_canary_source_changed",
        "runtime_canary_source_dirty",
        "runtime_canary_source_invalid",
        "runtime_canary_timeout",
        "runtime_canary_unit_collision",
        "runtime_canary_unit_identity_invalid",
    }
    return mapped if mapped in allowed else "runtime_canary_failed"


def canary(
    *,
    home: Path,
    systemctl: Systemctl = _systemctl_default,
    systemd_run: SystemdRun = _systemd_run_default,
) -> dict[str, object]:
    """Run one isolated transient diagnostic and prove complete quiescence."""

    generation: str | None = None
    manifest_digest: str | None = None
    result = _canary_result(
        status_code="runtime_canary_failed",
        error_code="runtime_canary_failed",
        generation=None,
        manifest_digest=None,
    )
    invocation = Path()
    binding: _CanaryUnitBinding | None = None
    launch_attempted = False
    ownership_attested = False
    root = _canary_runtime_root()
    try:
        _validate_canary_home(home)
        repository = Path(__file__).resolve().parents[2]
        source_commit, source_tree_digest = _source_tree_binding(repository)
        with _canary_lock(root):
            try:
                if _source_tree_binding(repository) != (
                    source_commit,
                    source_tree_digest,
                ):
                    raise _error("runtime_canary_source_changed")
                invocation = Path(
                    tempfile.mkdtemp(prefix=_CANARY_RUN_PREFIX, dir=os.fspath(root))
                )
                _private_directory(invocation)
                image = _prepare_canary_image(
                    repository=repository,
                    invocation_root=invocation,
                    source_commit=source_commit,
                )
                generation = image.generation
                manifest_digest = image.manifest_digest
                if _source_tree_binding(repository) != (
                    source_commit,
                    source_tree_digest,
                ):
                    raise _error("runtime_canary_source_changed")
                binding = _canary_unit_binding(
                    image=image,
                    home=home,
                    nonce=secrets.token_hex(16),
                )
                before = _canary_show(systemctl, binding.name)
                if before.get("LoadState") != "not-found":
                    raise _error("runtime_canary_unit_collision")
                launch_attempted = True
                _start_canary_unit(systemd_run, binding)
                manager_state = _wait_for_canary_result(systemctl, binding)
                ownership_attested = True
                if _source_tree_binding(repository) != (
                    source_commit,
                    source_tree_digest,
                ):
                    raise _error("runtime_canary_source_changed")
                status_code, error_code = _canary_evidence_result(
                    image=image, manager_state=manager_state
                )
                result = _canary_result(
                    status_code=status_code,
                    error_code=error_code,
                    generation=generation,
                    manifest_digest=manifest_digest,
                )
            finally:
                cleanup_ok = True
                if launch_attempted and binding is not None:
                    cleanup_ok = _cleanup_canary_unit(
                        systemctl,
                        binding,
                        ownership_attested=ownership_attested,
                    )
                if invocation != Path():
                    cleanup_ok = (
                        _remove_canary_invocation(root=root, invocation=invocation)
                        and cleanup_ok
                    )
                if not cleanup_ok:
                    raise _error("runtime_canary_cleanup_unverified")
    except RuntimeLifecycleError as exc:
        code = str(exc)
        result = _canary_result(
            status_code=(
                "runtime_canary_cleanup_failed"
                if code == "runtime_canary_cleanup_unverified"
                else "runtime_canary_failed"
            ),
            error_code=(
                code
                if code == "runtime_canary_cleanup_unverified"
                else _canary_public_failure(code)
            ),
            generation=generation,
            manifest_digest=manifest_digest,
        )
    except Exception:
        result = _canary_result(
            status_code="runtime_canary_failed",
            error_code="runtime_canary_failed",
            generation=generation,
            manifest_digest=manifest_digest,
        )
    return result


@contextmanager
def _lifecycle_lock(home: Path):
    lock = home / ".local" / "state" / "codex-master-mcp" / "hive" / _LOCK_NAME
    descriptor = -1
    try:
        for directory in (
            home / ".local",
            home / ".local" / "state",
            home / ".local" / "state" / "codex-master-mcp",
        ):
            _private_directory(directory)
        try:
            _private_directory(lock.parent)
        except RuntimeLifecycleError as exc:
            if str(exc) != "runtime_lifecycle_lock_invalid":
                raise
            try:
                lock.parent.mkdir(mode=0o700)
            except FileExistsError:
                pass
            except OSError as create_exc:
                raise _error("runtime_lifecycle_lock_invalid") from create_exc
            _private_directory(lock.parent)
        descriptor = os.open(
            lock,
            os.O_RDWR
            | os.O_CREAT
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise _error("runtime_lifecycle_lock_invalid")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise _error("runtime_lifecycle_busy") from exc
        yield
    except RuntimeLifecycleError:
        raise
    except OSError as exc:
        raise _error("runtime_lifecycle_lock_invalid") from exc
    finally:
        if descriptor >= 0:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)


def cutover(
    *, home: Path, systemctl: Systemctl = _systemctl_default
) -> dict[str, object]:
    """Run the sole D298 mutating runtime/user-manager transaction."""

    try:
        with _lifecycle_lock(home):
            bound = _bind_systemd_states(_bind_cutover_inputs(home), systemctl)
            # A completely verified target is a no-op; it must not re-install
            # an image or perturb the user manager merely to prove idempotence.
            already_green = verify(home=home, systemctl=systemctl)
            if already_green.get("status") == "runtime_lifecycle_green":
                return already_green
            # This final rebind check deliberately remains outside the mutation
            # handler: a hostile replacement before installer entry must not
            # even cause a compensating manager reload.
            _revalidate_cutover_inputs(bound)
            try:
                # The preceding statement is immediately before crossing the
                # existing installer mutation boundary.
                _install_attested_runtime(home)
                post_install = _bind_post_install(home)
                if _legacy_requires_migration(bound):
                    _revalidate_legacy_units(bound)
                _revalidate_post_install(post_install, home)
                _cutover_systemctl_mutate(
                    systemctl,
                    ("daemon-reload",),
                    phase="before_activation_reload",
                )
                if _legacy_requires_migration(bound):
                    _revalidate_legacy_units(bound)
                    _revalidate_post_install(post_install, home)
                    _cutover_systemctl_mutate(
                        systemctl,
                        ("stop", _LEGACY_SERVICE),
                        phase="legacy_service_stop",
                    )
                    _revalidate_legacy_units(bound)
                    _revalidate_post_install(post_install, home)
                    _cutover_systemctl_mutate(
                        systemctl,
                        ("disable", "--now", _LEGACY_TIMER),
                        phase="legacy_timer_disable",
                    )
                _revalidate_post_install(post_install, home)
                _cutover_systemctl_mutate(
                    systemctl,
                    ("enable", "--now", _NEW_TIMER),
                    phase="new_timer_enable",
                )
                _revalidate_post_install(post_install, home)
                _cutover_systemctl_mutate(
                    systemctl,
                    ("start", _NEW_SERVICE),
                    phase="new_service_start",
                )
                _revalidate_post_install(post_install, home)
                _observe_argumentless_installed_probe(home)
                _remove_legacy_hourly_units(bound)
                _revalidate_post_install(post_install, home)
                _cutover_systemctl_mutate(
                    systemctl,
                    ("daemon-reload",),
                    phase="after_unit_removal_reload",
                )
                result = verify(home=home, systemctl=systemctl)
                if result.get("status") != "runtime_lifecycle_green":
                    raise _error("runtime_lifecycle_postconditions_failed")
                return result
            except RuntimeLifecycleError as exc:
                rollback = _restore_bound_state_result(bound, systemctl)
                if not rollback.restored:
                    if not _publish_rollback_failure(bound):
                        return _rollback_failure_result(
                            status="runtime_lifecycle_rollback_alarm_failed",
                            rollback=rollback,
                        )
                    return _rollback_failure_result(
                        status="runtime_lifecycle_rollback_failed", rollback=rollback
                    )
                if isinstance(exc, _CutoverMutationError):
                    return _cutover_mutation_failure_result(exc)
                raise
    except RuntimeLifecycleError as exc:
        return {"status": str(exc), "raw_output": "not_returned"}


def main() -> int:
    parser = argparse.ArgumentParser(prog="the-hive-runtime-service")
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("canary", "cutover", "status", "verify"):
        child = commands.add_parser(command)
        child.add_argument("--home", type=Path, required=True)
    arguments = parser.parse_args()
    operation = {
        "canary": canary,
        "cutover": cutover,
        "status": status,
        "verify": verify,
    }[arguments.command]
    result = operation(home=arguments.home)
    print(json.dumps(result, sort_keys=True))
    return (
        0
        if result.get("status")
        in {"runtime_canary_green", "runtime_lifecycle_green"}
        else 1
    )


__all__ = ["canary", "cutover", "main", "status", "verify"]
