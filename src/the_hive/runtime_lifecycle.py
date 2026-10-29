"""Fail-closed lifecycle transactions for the hourly-probe runtime.

``cutover`` owns the canonical runtime.  ``canary`` owns only one isolated,
disposable transient unit and private image.  ``status`` and ``verify`` only
inspect bounded local data and systemd's user-manager state.
"""

from __future__ import annotations

import argparse
import ast
import base64
import contextlib
import ctypes
from datetime import UTC, datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import secrets
import selectors
import signal
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
from typing import cast

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
_HOURLY_PROBE_PROTECTED_HOME_BUS_BINDING = "BindReadOnlyPaths=%t/bus:%t/bus:norbind"
_HOURLY_PROBE_PROTECTED_HOME_MANAGER_BINDING = (
    "BindReadOnlyPaths=%t/systemd/private:%t/systemd/private:norbind"
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
_ROOT_HOOK_ABI_PARENT = Path("/usr/local/libexec/the-hive/hook-abi")
_ROOT_HOOK_ABI_UID = 0
_ROOT_HOOK_ABI_GID = 0
_ROOT_HOOK_EFFECT_RECEIPT = "root-hook-effect-receipt-v1.json"
_ROOT_HOOK_UPGRADE_STATE = ".root-hook-abi-upgrade-v1.json"
_SHA256_HEX_PATTERN = r"[0-9a-f]{64}"
_ROOT_HOOK_MANIFEST_DIGEST_PATTERN = rf"sha256:{_SHA256_HEX_PATTERN}"
_PLUGIN_EFFECT_RECEIPT = "plugin-release-effect-receipt-v1.json"
_OWNER_RECEIPT_FRESHNESS_NS = 3_600 * 1_000_000_000
_OBSERVATION_NAME = "runtime-lifecycle-probe-observation.json"
_MAX_OBSERVATION_BYTES = 4096
_PROBE_OBSERVATION_SECONDS = 120.0
_PROBE_OUTPUT_BYTES = 16 * 1024
_CANARY_UNIT_PREFIX = "the-hive-runtime-canary-"
_CANARY_RUNTIME_ROOT_NAME = "the-hive-runtime-canary"
_CANARY_LOCK_NAME = ".canary.lock"
_CANARY_QUALIFICATION_NAME = "qualification-v1.json"
_MAX_CANARY_QUALIFICATION_BYTES = 32 * 1024
_CANARY_QUALIFICATION_CRITERIA = frozenset(
    {
        "client_compatibility",
        "client_behavior",
        "client_probe",
        "manager_api_contract",
        "manager_actions",
        "runtime_canary",
        "runtime_features",
    }
)
_CANONICAL_CODEX_WRAPPER = Path("/usr/local/bin/codex")
_CANARY_RUN_PREFIX = "run-"
_CANARY_MANAGER_START_SECONDS = 15.0
_CANARY_RESULT_SECONDS = 112.0
_CANARY_CLEANUP_SECONDS = 5.0
_CANARY_CLIENT_COMMAND_SECONDS = 10.0
_CANARY_CLIENT_OUTPUT_BYTES = 16 * 1024
_CANARY_HEALTH_BYTES = 64 * 1024
_USER_RUNTIME_DIRECTORY_ROOT = Path("/run/user")
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
    "--property=LoadState,ActiveState,Description,Transient,Result,ExecMainStatus"
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
    "_PRODUCER_SOURCE_MANIFEST_SHA256": "d08706fbbc4e7b99c769787e42dd4c4ef4b956b1e3ec8fb0175acb8c58c566b6",
    "_PRODUCER_RELEASE_ID": "0.6.542-d08706fbbc4e7b99",
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
            status if self.status_whitelisted else "runtime_lifecycle_systemd_failed"
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
    payload_bytes = _d320_bytes_copy(payload_bytes, code="d320_envelope_too_large")
    if len(payload_bytes) + _D320_ENVELOPE_FIXED_BYTES > _D320_MAX_ENVELOPE_BYTES:
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
    payload_bytes = _d320_bytes_copy(payload_bytes, code="d320_wrapper_bytes_invalid")
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
            result.append(_d320_normalize_json_value(item, budget=traversal_budget))
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
        if generations != sorted(generations) or len(generations) != len(
            set(generations)
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
    if all(precutover[name] == postcutover[name] for name in _D320_ARTIFACT_NAMES):
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
    return b'{"content_sha256":"' + digest + b'","payload":' + payload_bytes + b"}\n"


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


_V2_FILE_PATHS = (
    ".local/lib/the-hive-runtime/.the-hive-release-pointers.json",
    ".local/lib/the-hive-runtime/the-hive-mcp",
    ".local/libexec/codex_master_hive_hourly_probe.py",
    ".local/bin/the-hive-openai-pricing-inventory",
    ".local/state/codex-master-mcp/runtime-lifecycle-probe-observation.json",
    *(
        ".config/systemd/user/" + name
        for name in (
            _NEW_SERVICE,
            _NEW_TIMER,
            *_PRICING_UNITS,
            _LEGACY_SERVICE,
            _LEGACY_TIMER,
        )
    ),
)
_V2_MANAGER_UNITS = (
    _NEW_SERVICE,
    _NEW_TIMER,
    _LEGACY_SERVICE,
    _LEGACY_TIMER,
    *_PRICING_UNITS,
)
_V2_PHASES = frozenset(
    {
        "INTENT",
        "SEALED",
        "INSTALLED",
        "ACTIVATED",
        "OBSERVED",
        "COMMITTED",
        "RECOVERING",
        "ROLLED_BACK",
        "BLOCKED",
    }
)


def _v2_expected_effects(
    home: Path, source_commit: str, stage_name: str
) -> dict[str, str]:
    return {
        str(home / relative): kind
        for kind, relative in (
            ("state_parent", ".local/state"),
            ("install_state", ".local/state/codex-master-mcp"),
            ("local_bin", ".local/bin"),
            ("local_libexec", ".local/libexec"),
            ("hook_pin_authority", ".local/state/the-hive/hook-session-pins-v1"),
            ("hook_pin_parent", ".local/state/the-hive"),
            (
                "hook_pin_lock",
                ".local/state/the-hive/hook-session-pins-v1/.hook-session-pins-v1.lock",
            ),
            ("probe_lock", ".local/state/codex-master-mcp/.hive-hourly-probe.lock"),
            ("config", ".config"),
            ("config_systemd", ".config/systemd"),
            ("units", ".config/systemd/user"),
            ("library", ".local/lib"),
            ("release_root", ".local/lib/the-hive-runtime"),
            ("generations", ".local/lib/the-hive-runtime/generations"),
            ("stage", ".local/lib/" + stage_name),
            (
                "generation",
                ".local/lib/the-hive-runtime/generations/" + source_commit,
            ),
            (
                "publish_lock",
                ".local/lib/the-hive-runtime/.the-hive-release-publish.lock",
            ),
            (
                "lifecycle_lock",
                ".local/state/codex-master-mcp/hive/.runtime-lifecycle.lock",
            ),
            (
                "journal",
                ".local/state/codex-master-mcp/hive/runtime-lifecycle-journal-v2.json",
            ),
        )
    }


def _v2_plan_effects(home: Path, source_commit: str) -> list[dict[str, str]]:
    stage_name = ".the-hive-runtime.stage.<transaction-id>"
    stage_path = str(home / ".local" / "lib" / stage_name)
    effects = _v2_expected_effects(home, source_commit, stage_name)
    return [
        (
            {"kind": kind, "path_template": path}
            if path == stage_path
            else {"kind": kind, "path": path}
        )
        for path, kind in sorted(effects.items())
    ]


def _v2_validate_identity(
    kind: str, value: object, *, owner_uid: int
) -> Mapping[str, object]:
    identity = _d320_object(
        value,
        ("type", "dev", "ino", "uid", "gid", "mode", "nlink", "children"),
        code="d320_v2_identity_invalid",
    )
    if identity["type"] == "absent":
        if (
            any(
                identity[key] is not None
                for key in ("dev", "ino", "uid", "gid", "mode", "nlink")
            )
            or identity["children"] != []
        ):
            _d320_fail("d320_v2_identity_invalid")
        return identity
    expected_type = (
        "directory"
        if kind
        in {
            "state_parent",
            "install_state",
            "local_bin",
            "local_libexec",
            "config",
            "config_systemd",
            "units",
            "hook_pin_authority",
            "hook_pin_parent",
            "library",
            "release_root",
            "generations",
            "stage",
            "generation",
        }
        else "file"
    )
    if identity["type"] != expected_type:
        _d320_fail("d320_v2_identity_invalid")
    for key in ("dev", "ino", "uid", "gid", "mode", "nlink"):
        _d320_int(identity[key], minimum=0)
    if identity["uid"] != owner_uid:
        _d320_fail("d320_v2_identity_owner_invalid")
    if expected_type == "file" and (
        identity["nlink"] != 1 or identity["mode"] != 0o600
    ):
        _d320_fail("d320_v2_identity_file_invalid")
    if expected_type == "directory" and identity["mode"] != 0o700:
        _d320_fail("d320_v2_identity_directory_invalid")
    children = identity["children"]
    if (
        not isinstance(children, list)
        or children != sorted(set(children))
        or not all(
            isinstance(name, str) and name not in {".", ".."} for name in children
        )
    ):
        _d320_fail("d320_v2_identity_children_invalid")
    if kind == "generations" and any(
        re.fullmatch(r"[0-9a-f]{40}", name) is None for name in children
    ):
        _d320_fail("d320_v2_identity_children_invalid")
    return identity


def _v2_validate_files(
    value: object, *, home: Path, aggregate: list[int]
) -> list[Mapping[str, object]]:
    if not isinstance(value, list) or len(value) != len(_V2_FILE_PATHS):
        _d320_fail("d320_v2_files_invalid")
    expected_files = {str(home / relative) for relative in _V2_FILE_PATHS}
    seen: set[str] = set()
    result: list[Mapping[str, object]] = []
    for item in value:
        snapshot = _d320_validate_snapshot(item, aggregate=aggregate)
        path = snapshot["path"]
        if (
            path not in expected_files
            or path in seen
            or snapshot["name"] != Path(path).name
        ):
            _d320_fail("d320_v2_files_invalid")
        seen.add(path)
        result.append(snapshot)
    if seen != expected_files:
        _d320_fail("d320_v2_files_invalid")
    return result


def _v2_validate_effects(
    value: object,
    *,
    home: Path,
    source_commit: str,
    stage_name: str,
    owner_uid: int,
) -> list[Mapping[str, object]]:
    expected = _v2_expected_effects(home, source_commit, stage_name)
    if not isinstance(value, list) or len(value) != len(expected):
        _d320_fail("d320_v2_effects_invalid")
    seen: set[str] = set()
    result: list[Mapping[str, object]] = []
    for item in value:
        effect = _d320_object(
            item,
            ("kind", "path", "present", "identity"),
            code="d320_v2_effect_invalid",
        )
        path = effect["path"]
        kind = expected.get(path) if isinstance(path, str) else None
        if (
            kind is None
            or path in seen
            or effect["kind"] != kind
            or type(effect["present"]) is not bool
        ):
            _d320_fail("d320_v2_effect_invalid")
        identity = _v2_validate_identity(kind, effect["identity"], owner_uid=owner_uid)
        if effect["present"] != (identity["type"] != "absent"):
            _d320_fail("d320_v2_effect_invalid")
        seen.add(path)
        result.append(effect)
    if seen != set(expected):
        _d320_fail("d320_v2_effects_invalid")
    return result


def _v2_validate_manager_states(value: object) -> Mapping[str, Mapping[str, str]]:
    if (
        not isinstance(value, dict)
        or set(value) != set(_V2_MANAGER_UNITS)
        or any(
            not isinstance(state, dict) or not _valid_bound_unit_state(state)
            for state in value.values()
        )
    ):
        _d320_fail("d320_v2_manager_invalid")
    return value


_V2_STEP_ACTIONS = {
    "INTENT": {"intent_persisted", "effect_created"},
    "SEALED": {"stage_sealed"},
    "INSTALLED": {"effect_installed", "generation_published"},
    "ACTIVATED": {"manager_mutation", "effect_installed", "owner_evidence_readback"},
    "OBSERVED": {"effect_readback", "manager_readback", "owner_evidence_readback"},
    "COMMITTED": {"commit_verified"},
    "RECOVERING": {"recovery_started", "inverse_reserved", "inverse_applied"},
    "ROLLED_BACK": {"rollback_verified"},
    "BLOCKED": {"blocked"},
}
_V2_PHASE_ORDER = {phase: index for index, phase in enumerate(_V2_STEP_ACTIONS)}
_V2_JOURNAL_ACTIONS = {
    "intent_persisted",
    "commit_verified",
    "recovery_started",
    "rollback_verified",
    "blocked",
}


def _v2_validate_steps(
    value: object,
    *,
    phase: str,
    sequence: int,
    journal_path: str,
    expected_files: set[str],
    expected_effects: Mapping[str, str],
    expected_setup_temps: Mapping[str, str],
) -> list[Mapping[str, object]]:
    home = Path(journal_path).parents[4]
    if not isinstance(value, list) or not 1 <= len(value) <= 128:
        _d320_fail("d320_v2_steps_invalid")
    result: list[Mapping[str, object]] = []
    prior_sequence = 0
    prior_phase_index = -1
    seen_events: set[tuple[str, str, str]] = set()
    for item in value:
        step = _d320_object(
            item,
            ("sequence", "phase", "action", "effect", "sha256"),
            code="d320_v2_step_invalid",
        )
        event_sequence = _d320_int(step["sequence"], minimum=1, maximum=sequence)
        event_phase = _d320_text(step["phase"], maximum=32, ascii_only=True)
        action = _d320_text(step["action"], maximum=32, ascii_only=True)
        effect = _d320_text(step["effect"], maximum=4096)
        _d320_sha256(step["sha256"])
        if event_phase not in _V2_PHASES or action not in _V2_STEP_ACTIONS[event_phase]:
            _d320_fail("d320_v2_step_invalid")
        manager_name = effect.removeprefix("manager:")
        owner_receipt_paths = {
            str(_ROOT_HOOK_ABI_PARENT / _ROOT_HOOK_EFFECT_RECEIPT),
            str(home / ".local/state/codex-master-mcp/hive" / _PLUGIN_EFFECT_RECEIPT),
        }
        path_effect = (
            effect in expected_files
            or effect in expected_effects
            or effect in expected_setup_temps
        )
        if action == "owner_evidence_readback":
            bound_effect = (
                event_phase in {"ACTIVATED", "OBSERVED"}
                and effect in owner_receipt_paths
            )
        elif action in _V2_JOURNAL_ACTIONS:
            bound_effect = effect == journal_path
        elif action == "effect_created":
            bound_effect = effect in expected_setup_temps
        elif action == "stage_sealed":
            bound_effect = expected_effects.get(effect) == "stage"
        elif action == "generation_published":
            bound_effect = expected_effects.get(effect) == "generation"
        elif action in {"manager_mutation", "manager_readback"}:
            bound_effect = (
                effect.startswith("manager:") and manager_name in _V2_MANAGER_UNITS
            )
        else:
            bound_effect = path_effect
        if not bound_effect:
            _d320_fail("d320_v2_step_binding_invalid")
        phase_index = _V2_PHASE_ORDER[event_phase]
        if event_sequence != prior_sequence + 1 or phase_index < prior_phase_index:
            _d320_fail("d320_v2_step_order_invalid")
        event = (event_phase, action, effect)
        if event in seen_events and action != "owner_evidence_readback":
            _d320_fail("d320_v2_step_duplicate")
        seen_events.add(event)
        result.append(step)
        prior_sequence = event_sequence
        prior_phase_index = phase_index
    if result[-1]["phase"] != phase or result[-1]["sequence"] != sequence:
        _d320_fail("d320_v2_step_head_invalid")
    if result[0]["phase"] != "INTENT" or result[0]["action"] != "intent_persisted":
        _d320_fail("d320_v2_intent_step_missing")
    if phase == "INTENT" and any(
        step["action"] != "intent_persisted" and step["action"] != "effect_created"
        for step in result
    ):
        _d320_fail("d320_v2_intent_step_invalid")
    return result


def _v2_validate_post(
    value: object,
    *,
    home: Path,
    source_commit: str,
    stage_name: str,
    owner_uid: int,
    phase: str,
    steps: Sequence[Mapping[str, object]],
) -> Mapping[str, object]:
    if phase not in {"OBSERVED", "COMMITTED", "RECOVERING", "ROLLED_BACK", "BLOCKED"}:
        _d320_fail("d320_v2_post_phase_invalid")
    post = _d320_object(
        value,
        ("files", "extra_effects", "manager_states"),
        code="d320_v2_post_invalid",
    )
    files = _v2_validate_files(post["files"], home=home, aggregate=[0])
    effects = _v2_validate_effects(
        post["extra_effects"],
        home=home,
        source_commit=source_commit,
        stage_name=stage_name,
        owner_uid=owner_uid,
    )
    manager = _v2_validate_manager_states(post["manager_states"])
    readbacks = {
        step["effect"]: step["sha256"]
        for step in steps
        if step["phase"] == "OBSERVED"
        and step["action"] in {"effect_readback", "manager_readback"}
    }
    expected_readbacks = {
        item["path"]: hashlib.sha256(_d320_canonical_json(item)).hexdigest()
        for item in (*files, *effects)
    } | {
        "manager:" + unit: hashlib.sha256(_d320_canonical_json(state)).hexdigest()
        for unit, state in manager.items()
    }
    if readbacks != expected_readbacks:
        _d320_fail("d320_v2_post_readback_incomplete")
    return post


def _v2_validate_payload(value: object) -> dict[str, object]:
    fields = {
        "schema",
        "mode",
        "journal_id",
        "transaction_id",
        "lock_generation",
        "sequence",
        "phase",
        "plan_sha256",
        "plan",
        "source",
        "target",
        "owner_uid",
        "predecessor",
        "stage_name",
        "files",
        "extra_effects",
        "manager_pre",
        "inverse_actions",
        "sealed",
        "post",
        "recovery_count",
        "steps",
    }
    if (
        not isinstance(value, dict)
        or set(value) != fields
        or value["schema"] != "D320CutoverJournalV2"
        or value["mode"] != "runtime_lifecycle"
    ):
        _d320_fail("d320_v2_schema_invalid")
    _d320_text(value["journal_id"], maximum=128, ascii_only=True)
    for key in (
        "transaction_id",
        "lock_generation",
        "sequence",
        "owner_uid",
        "recovery_count",
    ):
        _d320_int(value[key])
    _d320_sha256(value["plan_sha256"])
    plan = _d320_object(
        value["plan"],
        (
            "schema",
            "mode",
            "source",
            "target",
            "owner_uid",
            "predecessor",
            "compatibility",
            "qualification",
            "files",
            "extra_effects",
            "manager_states",
            "actions",
            "inverse_actions",
            "output_manifest_digest",
        ),
        code="d320_v2_plan_invalid",
    )
    compatibility = _d320_object(
        plan["compatibility"],
        ("status", "sha256"),
        code="d320_v2_plan_compatibility_invalid",
    )
    if compatibility["status"] != "qualified":
        _d320_fail("d320_v2_plan_compatibility_invalid")
    _d320_sha256(compatibility["sha256"])
    qualification = plan["qualification"]
    qualification = _d320_object(
        qualification,
        ("status", "issued_at_unix_ns", "sha256"),
        code="d320_v2_plan_qualification_invalid",
    )
    if (
        qualification["status"] != "qualified"
        or type(qualification["issued_at_unix_ns"]) is not int
        or qualification["issued_at_unix_ns"] <= 0
    ):
        _d320_fail("d320_v2_plan_qualification_invalid")
    _d320_sha256(qualification["sha256"])
    if (
        plan["schema"] != "D320RuntimeCutoverPlanV2"
        or plan["mode"] != "runtime_lifecycle"
        or hashlib.sha256(_d320_canonical_json(plan)).hexdigest()
        != value["plan_sha256"]
    ):
        _d320_fail("d320_v2_plan_invalid")
    source = _d320_object(
        value["source"], ("commit", "tree_sha256"), code="d320_v2_source_invalid"
    )
    _d320_git_hex(source["commit"])
    _d320_sha256(source["tree_sha256"])
    target = _d320_object(
        value["target"],
        ("realpath", "dev", "ino", "uid", "gid", "mode"),
        code="d320_v2_target_invalid",
    )
    home = Path(_d320_validate_absolute_path(target["realpath"]))
    for key in ("dev", "ino", "uid", "gid", "mode"):
        _d320_int(target[key], minimum=0)
    owner_uid = _d320_int(value["owner_uid"])
    if target["uid"] != owner_uid:
        _d320_fail("d320_v2_owner_invalid")
    predecessor = _d320_object(
        value["predecessor"],
        ("generation", "manifest_digest", "consumer_sha256"),
        code="d320_v2_predecessor_invalid",
    )
    plan_predecessor = _d320_object(
        plan["predecessor"],
        ("generation", "manifest_digest", "consumer_pin", "consumer_sha256"),
        code="d320_v2_plan_invalid",
    )
    if (
        plan["source"] != source
        or plan["target"] != target
        or plan["owner_uid"] != owner_uid
        or plan_predecessor["consumer_pin"] is not True
        or plan_predecessor["generation"] != predecessor["generation"]
        or plan_predecessor["manifest_digest"] != predecessor["manifest_digest"]
        or plan_predecessor["consumer_sha256"] != predecessor["consumer_sha256"]
        or plan["actions"] != ["install", "activate", "observe", "commit"]
        or plan["inverse_actions"]
        != ["restore_manager", "restore_files", "discard_generation"]
        or plan["output_manifest_digest"] != "pending"
    ):
        _d320_fail("d320_v2_plan_binding_invalid")
    _d320_git_hex(predecessor["generation"])
    digest = predecessor["manifest_digest"]
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        _d320_fail("d320_v2_predecessor_invalid")
    _d320_sha256(digest[7:])
    _d320_sha256(predecessor["consumer_sha256"])
    stage_name = _d320_text(value["stage_name"], maximum=96, ascii_only=True)
    if (
        not isinstance(stage_name, str)
        or re.fullmatch(r"\.the-hive-runtime\.stage\.[A-Za-z0-9-]{1,64}", stage_name)
        is None
    ):
        _d320_fail("d320_v2_stage_invalid")
    aggregate = [0]
    snapshots = _v2_validate_files(value["files"], home=home, aggregate=aggregate)
    expected_files = {snapshot["path"] for snapshot in snapshots}
    plan_files = plan["files"]
    if not isinstance(plan_files, list) or len(plan_files) != len(snapshots):
        _d320_fail("d320_v2_plan_files_invalid")
    plan_by_path = {
        item.get("path"): item for item in plan_files if isinstance(item, dict)
    }
    if len(plan_by_path) != len(plan_files) or set(plan_by_path) != expected_files:
        _d320_fail("d320_v2_plan_files_invalid")
    for snapshot in snapshots:
        planned = plan_by_path[snapshot["path"]]
        if (
            planned.get("name") != snapshot["name"]
            or planned.get("present") != snapshot["present"]
            or planned.get("sha256") != snapshot["sha256"]
            or planned.get("mode") != snapshot["mode"]
            or any(
                planned.get(key) != snapshot[key]
                for key in ("dev", "ino", "uid", "gid", "nlink")
            )
        ):
            _d320_fail("d320_v2_plan_files_invalid")
    expected_effects = _v2_expected_effects(home, source["commit"], stage_name)
    if plan["extra_effects"] != _v2_plan_effects(home, source["commit"]):
        _d320_fail("d320_v2_plan_effects_invalid")
    _v2_validate_effects(
        value["extra_effects"],
        home=home,
        source_commit=source["commit"],
        stage_name=stage_name,
        owner_uid=owner_uid,
    )
    _v2_validate_manager_states(value["manager_pre"])
    if plan["manager_states"] != value["manager_pre"]:
        _d320_fail("d320_v2_plan_binding_invalid")
    if value["inverse_actions"] != [
        "restore_manager",
        "restore_files",
        "discard_generation",
    ]:
        _d320_fail("d320_v2_inverse_invalid")
    phase = _d320_text(value["phase"], maximum=32, ascii_only=True)
    if phase not in _V2_PHASES:
        _d320_fail("d320_v2_phase_invalid")
    sealed = value["sealed"]
    if sealed is not None:
        seal = _d320_object(
            sealed,
            (
                "generation",
                "manifest_digest",
                "output_sha256",
                "stage_identity_sha256",
                "generation_identity_sha256",
            ),
            code="d320_v2_seal_invalid",
        )
        if seal["generation"] != source["commit"]:
            _d320_fail("d320_v2_seal_invalid")
        manifest_digest = seal["manifest_digest"]
        if not isinstance(manifest_digest, str) or not manifest_digest.startswith(
            "sha256:"
        ):
            _d320_fail("d320_v2_seal_invalid")
        _d320_sha256(manifest_digest[7:])
        _d320_sha256(seal["stage_identity_sha256"])
        _d320_sha256(seal["generation_identity_sha256"])
        outputs = seal["output_sha256"]
        if not isinstance(outputs, dict) or set(outputs) != {
            "mcp_launcher",
            "hourly_service",
            "hourly_timer",
            "pricing_launcher",
            "pricing_service",
            "pricing_timer",
            "legacy_launcher",
        }:
            _d320_fail("d320_v2_seal_invalid")
        for output_digest in outputs.values():
            _d320_sha256(output_digest)
    if (
        phase in {"SEALED", "INSTALLED", "ACTIVATED", "OBSERVED", "COMMITTED"}
        and sealed is None
    ):
        _d320_fail("d320_v2_phase_seal_invalid")
    journal_path = str(
        home
        / ".local"
        / "state"
        / "codex-master-mcp"
        / "hive"
        / "runtime-lifecycle-journal-v2.json"
    )
    expected_setup_temps = {
        str(_v2_setup_temp_path({"stage_name": stage_name}, Path(path))): path
        for path in expected_effects
    }
    steps = _v2_validate_steps(
        value["steps"],
        phase=phase,
        sequence=_d320_int(value["sequence"], minimum=1),
        journal_path=journal_path,
        expected_files=expected_files,
        expected_effects=expected_effects,
        expected_setup_temps=expected_setup_temps,
    )
    seal_digest = (
        sealed["manifest_digest"][7:]
        if isinstance(sealed, Mapping)
        and isinstance(sealed.get("manifest_digest"), str)
        else None
    )
    sealed_steps = [step for step in steps if step["action"] == "stage_sealed"]
    if (sealed is None and sealed_steps) or (
        sealed is not None
        and (len(sealed_steps) != 1 or sealed_steps[0]["sha256"] != seal_digest)
    ):
        _d320_fail("d320_v2_seal_step_invalid")
    if any(
        step["action"] == "generation_published" and step["sha256"] != seal_digest
        for step in steps
    ):
        _d320_fail("d320_v2_publish_step_invalid")
    has_observation = any(
        step["phase"] == "OBSERVED"
        and step["action"] in {"effect_readback", "manager_readback"}
        for step in steps
    )
    if value["post"] is None and has_observation:
        _d320_fail("d320_v2_post_missing")
    if value["post"] is not None:
        _v2_validate_post(
            value["post"],
            home=home,
            source_commit=source["commit"],
            stage_name=stage_name,
            owner_uid=owner_uid,
            phase=phase,
            steps=steps,
        )
    elif phase in {"OBSERVED", "COMMITTED"}:
        _d320_fail("d320_v2_post_missing")
    return value


class D320CutoverJournalV2(bytes):
    """A distinct runtime-lifecycle journal; it never accepts V1 payloads."""

    __slots__ = ()

    @classmethod
    def from_payload(cls, value: Mapping[str, object]) -> D320CutoverJournalV2:
        if cls is not D320CutoverJournalV2:
            _d320_fail("d320_v2_type_invalid")
        payload = _d320_canonical_json(value)
        _d320_validate_envelope_payload_size(payload)
        _v2_validate_payload(_d320_parse_json(payload))
        if len(_d320_journal_envelope(payload)) > _D320_MAX_ENVELOPE_BYTES:
            _d320_fail("d320_v2_envelope_too_large")
        return bytes.__new__(cls, payload)

    @classmethod
    def from_bytes(cls, raw: bytes) -> D320CutoverJournalV2:
        copied = _d320_bytes_copy(raw, code="d320_v2_envelope_invalid")
        if len(copied) > _D320_MAX_ENVELOPE_BYTES or not copied.endswith(b"\n"):
            _d320_fail("d320_v2_envelope_invalid")
        envelope = _d320_parse_json(copied[:-1])
        if not isinstance(envelope, dict) or set(envelope) != {
            "content_sha256",
            "payload",
        }:
            _d320_fail("d320_v2_envelope_invalid")
        result = cls.from_payload(envelope["payload"])
        if copied != result.to_bytes():
            _d320_fail("d320_v2_envelope_invalid")
        return result

    @property
    def payload(self) -> dict[str, object]:
        parsed = _d320_parse_json(bytes(self))
        return _v2_validate_payload(parsed)

    def to_bytes(self) -> bytes:
        return _d320_journal_envelope(bytes(self))


_V2_PHASE_SUCCESSORS = {
    "INTENT": {"INTENT", "SEALED", "RECOVERING", "BLOCKED"},
    "SEALED": {"INSTALLED", "RECOVERING", "BLOCKED"},
    "INSTALLED": {"ACTIVATED", "RECOVERING", "BLOCKED"},
    "ACTIVATED": {"ACTIVATED", "OBSERVED", "RECOVERING", "BLOCKED"},
    "OBSERVED": {"OBSERVED", "COMMITTED", "RECOVERING", "BLOCKED"},
    "COMMITTED": set(),
    "RECOVERING": {"RECOVERING", "ROLLED_BACK", "BLOCKED"},
    "ROLLED_BACK": set(),
    "BLOCKED": set(),
}
_V2_IMMUTABLE_FIELDS = (
    "schema",
    "mode",
    "journal_id",
    "transaction_id",
    "lock_generation",
    "plan_sha256",
    "plan",
    "source",
    "target",
    "owner_uid",
    "predecessor",
    "stage_name",
    "files",
    "extra_effects",
    "manager_pre",
    "inverse_actions",
)


def validate_d320_v2_journal_successor(
    previous: D320CutoverJournalV2 | bytes,
    successor: D320CutoverJournalV2 | bytes,
) -> None:
    """Require one append-only, fenced phase transition from a valid V2 record."""

    if isinstance(previous, D320CutoverJournalV2):
        before = previous.payload
    else:
        before = D320CutoverJournalV2.from_bytes(previous).payload
    if isinstance(successor, D320CutoverJournalV2):
        after = successor.payload
    else:
        after = D320CutoverJournalV2.from_bytes(successor).payload
    if any(before[key] != after[key] for key in _V2_IMMUTABLE_FIELDS):
        _d320_fail("d320_v2_successor_identity_changed")
    before_sequence = _d320_int(before["sequence"], minimum=1)
    after_sequence = _d320_int(after["sequence"], minimum=1)
    before_phase = str(before["phase"])
    after_phase = str(after["phase"])
    if after_phase not in _V2_PHASE_SUCCESSORS[before_phase]:
        _d320_fail("d320_v2_successor_phase_invalid")
    before_steps = before["steps"]
    after_steps = after["steps"]
    appended = (
        after_steps[len(before_steps) :]
        if isinstance(before_steps, list) and isinstance(after_steps, list)
        else []
    )
    repeated_owner_evidence = (
        (before_phase, after_phase) == ("OBSERVED", "OBSERVED")
        and bool(appended)
        and all(step.get("action") == "owner_evidence_readback" for step in appended)
    )
    if (
        not isinstance(before_steps, list)
        or not isinstance(after_steps, list)
        or after_steps[: len(before_steps)] != before_steps
        or not appended
        or (
            len(appended) > 1
            and (before_phase, after_phase)
            not in {
                ("ACTIVATED", "OBSERVED"),
                ("INTENT", "INTENT"),
                ("SEALED", "INSTALLED"),
            }
            and not repeated_owner_evidence
        )
        or after_sequence != before_sequence + len(appended)
        or (
            (before_phase, after_phase) == ("OBSERVED", "OBSERVED")
            and not repeated_owner_evidence
        )
        or any(
            step["sequence"] != before_sequence + index + 1
            or step["phase"] != after_phase
            for index, step in enumerate(appended)
        )
    ):
        _d320_fail("d320_v2_successor_steps_invalid")
    previous_seal = before["sealed"]
    next_seal = after["sealed"]
    if previous_seal is not None and next_seal != previous_seal:
        _d320_fail("d320_v2_successor_seal_rewritten")
    if previous_seal is None and next_seal is not None and after_phase != "SEALED":
        _d320_fail("d320_v2_successor_seal_phase_invalid")
    previous_post = before["post"]
    next_post = after["post"]
    if previous_post is not None and next_post != previous_post:
        _d320_fail("d320_v2_successor_post_rewritten")
    if previous_post is None and next_post is not None and after_phase != "OBSERVED":
        _d320_fail("d320_v2_successor_post_phase_invalid")
    previous_recovery_count = _d320_int(before["recovery_count"], maximum=1024)
    next_recovery_count = _d320_int(after["recovery_count"], maximum=1024)
    expected_recovery_count = previous_recovery_count + int(
        before_phase != "RECOVERING" and after_phase == "RECOVERING"
    )
    if next_recovery_count != expected_recovery_count:
        _d320_fail("d320_v2_successor_recovery_count_invalid")


def _v2_journal_path(home: Path) -> Path:
    return (
        home
        / ".local"
        / "state"
        / "codex-master-mcp"
        / "hive"
        / "runtime-lifecycle-journal-v2.json"
    )


def _v2_load_journal(home: Path) -> D320CutoverJournalV2 | None:
    path = _v2_journal_path(home)
    try:
        path.parent.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise _error("runtime_lifecycle_journal_invalid") from exc
    try:
        _private_directory(path.parent)
        raw = _regular_bytes(path, maximum=_D320_MAX_ENVELOPE_BYTES, mode=0o600)
    except RuntimeLifecycleError:
        raise _error("runtime_lifecycle_journal_invalid")
    if raw is None:
        return None
    try:
        return D320CutoverJournalV2.from_bytes(raw)
    except D320CutoverJournalError as exc:
        raise _error("runtime_lifecycle_journal_invalid") from exc


def _v2_assert_lock_lease(home: Path, lease: _LifecycleLockLease) -> None:
    if (
        not isinstance(lease, _LifecycleLockLease)
        or not lease.active
        or lease.owner_pid != os.getpid()
        or lease.home != home.resolve(strict=True)
        or lease.lock_path
        != home / ".local" / "state" / "codex-master-mcp" / "hive" / _LOCK_NAME
    ):
        raise _error("runtime_lifecycle_lock_required")
    try:
        held = os.fstat(lease.descriptor)
        named = lease.lock_path.lstat()
    except OSError as exc:
        raise _error("runtime_lifecycle_lock_invalid") from exc
    if (
        (held.st_dev, held.st_ino) != lease.identity
        or (named.st_dev, named.st_ino) != lease.identity
        or not stat.S_ISREG(held.st_mode)
        or held.st_uid != os.geteuid()
        or held.st_nlink != 1
        or stat.S_IMODE(held.st_mode) != 0o600
    ):
        raise _error("runtime_lifecycle_lock_invalid")


def _v2_store_journal(
    home: Path,
    journal: D320CutoverJournalV2,
    *,
    expected_digest: str | None,
    lease: _LifecycleLockLease,
    previous: D320CutoverJournalV2 | None = None,
) -> None:
    """CAS-publish one validated journal under the shared lifecycle lock."""

    _v2_assert_lock_lease(home, lease)
    path = _v2_journal_path(home)
    try:
        _private_directory(path.parent)
        current = _regular_bytes(path, maximum=_D320_MAX_ENVELOPE_BYTES, mode=0o600)
    except RuntimeLifecycleError as exc:
        if str(exc) == "runtime_lifecycle_binding_invalid" and not path.exists():
            current = None
        else:
            raise _error("runtime_lifecycle_journal_invalid") from exc
    current_digest = (
        hashlib.sha256(current).hexdigest() if current is not None else None
    )
    if current_digest != expected_digest:
        raise _error("runtime_lifecycle_journal_changed")
    checked = D320CutoverJournalV2.from_bytes(journal.to_bytes())
    if previous is None:
        if checked.payload["phase"] != "INTENT":
            raise _error("runtime_lifecycle_journal_transition_invalid")
        if current is not None:
            try:
                terminal = D320CutoverJournalV2.from_bytes(current).payload
            except D320CutoverJournalError as exc:
                raise _error("runtime_lifecycle_journal_invalid") from exc
            if (
                terminal["phase"] not in {"COMMITTED", "ROLLED_BACK"}
                or checked.payload["transaction_id"] <= terminal["transaction_id"]
                or checked.payload["lock_generation"] <= terminal["lock_generation"]
            ):
                raise _error("runtime_lifecycle_journal_transition_invalid")
    else:
        if current != previous.to_bytes():
            raise _error("runtime_lifecycle_journal_changed")
        try:
            validate_d320_v2_journal_successor(previous, checked)
        except D320CutoverJournalError as exc:
            raise _error("runtime_lifecycle_journal_transition_invalid") from exc
    _v2_assert_lock_lease(home, lease)
    try:
        _atomic_restore(path, checked.to_bytes(), 0o600)
    except RuntimeLifecycleError as exc:
        raise _error("runtime_lifecycle_journal_write_failed") from exc


def _v2_capture_effects(
    home: Path, source_commit: str, stage_name: str
) -> list[dict[str, object]]:
    absent = {
        "type": "absent",
        "dev": None,
        "ino": None,
        "uid": None,
        "gid": None,
        "mode": None,
        "nlink": None,
        "children": [],
    }
    effects: list[dict[str, object]] = []
    for path, kind in sorted(
        _v2_expected_effects(home, source_commit, stage_name).items()
    ):
        target = Path(path)
        try:
            item = target.lstat()
        except FileNotFoundError:
            identity = dict(absent)
        except OSError as exc:
            raise _error("runtime_lifecycle_effect_unreadable") from exc
        else:
            if stat.S_ISLNK(item.st_mode) or item.st_uid != os.geteuid():
                raise _error("runtime_lifecycle_effect_identity_invalid")
            if stat.S_ISDIR(item.st_mode):
                try:
                    children = sorted(child.name for child in target.iterdir())
                except OSError as exc:
                    raise _error("runtime_lifecycle_effect_unreadable") from exc
                if any(
                    not name or name in {".", ".."} or "/" in name for name in children
                ):
                    raise _error("runtime_lifecycle_effect_identity_invalid")
                identity = {
                    "type": "directory",
                    "dev": item.st_dev,
                    "ino": item.st_ino,
                    "uid": item.st_uid,
                    "gid": item.st_gid,
                    "mode": stat.S_IMODE(item.st_mode),
                    "nlink": item.st_nlink,
                    "children": children,
                }
            elif stat.S_ISREG(item.st_mode) and item.st_nlink == 1:
                identity = {
                    "type": "file",
                    "dev": item.st_dev,
                    "ino": item.st_ino,
                    "uid": item.st_uid,
                    "gid": item.st_gid,
                    "mode": stat.S_IMODE(item.st_mode),
                    "nlink": item.st_nlink,
                    "children": [],
                }
            else:
                raise _error("runtime_lifecycle_effect_identity_invalid")
        effects.append(
            {
                "kind": kind,
                "path": path,
                "present": identity["type"] != "absent",
                "identity": identity,
            }
        )
    return effects


def _v2_effect_identity_digest(effect: Mapping[str, object]) -> str:
    identity = effect.get("identity")
    if not isinstance(identity, Mapping):
        raise _error("runtime_lifecycle_effect_identity_invalid")
    fields = ("type", "dev", "ino", "uid", "gid", "mode")
    if identity["type"] == "file":
        fields += ("nlink",)
    stable = {key: identity[key] for key in fields}
    return hashlib.sha256(_d320_canonical_json(stable)).hexdigest()


def _v2_initial_journal(
    bound: _BoundCutover,
    *,
    plan: Mapping[str, object],
    plan_sha256: str,
    stage_name: str,
    previous: D320CutoverJournalV2 | None,
) -> D320CutoverJournalV2:
    files: list[dict[str, object]] = []
    for path, content, _mode in bound.files:
        if content is None:
            snapshot: dict[str, object] = {
                "name": path.name,
                "path": str(path),
                "present": False,
                "bytes_b64": None,
                "sha256": None,
                "dev": None,
                "ino": None,
                "uid": None,
                "gid": None,
                "mode": None,
                "nlink": None,
                "size": None,
            }
        else:
            info = path.lstat()
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != os.geteuid()
            ):
                raise _error("runtime_lifecycle_input_changed")
            snapshot = {
                "name": path.name,
                "path": str(path),
                "present": True,
                "bytes_b64": base64.b64encode(content).decode("ascii"),
                "sha256": hashlib.sha256(content).hexdigest(),
                "dev": info.st_dev,
                "ino": info.st_ino,
                "uid": info.st_uid,
                "gid": info.st_gid,
                "mode": stat.S_IMODE(info.st_mode),
                "nlink": info.st_nlink,
                "size": len(content),
            }
        files.append(snapshot)
    target = dict(plan["target"])
    source = dict(plan["source"])
    predecessor = plan["predecessor"]
    manager_pre = {name: dict(value) for name, value in bound.states}
    transaction_id = (
        1 if previous is None else int(previous.payload["transaction_id"]) + 1
    )
    lock_generation = (
        1 if previous is None else int(previous.payload["lock_generation"]) + 1
    )
    journal_id = "runtime-lifecycle-v2-" + secrets.token_hex(16)
    path = str(_v2_journal_path(bound.home))
    payload = {
        "schema": "D320CutoverJournalV2",
        "mode": "runtime_lifecycle",
        "journal_id": journal_id,
        "transaction_id": transaction_id,
        "lock_generation": lock_generation,
        "sequence": 1,
        "phase": "INTENT",
        "plan_sha256": plan_sha256,
        "plan": dict(plan),
        "source": source,
        "target": target,
        "owner_uid": os.geteuid(),
        "predecessor": {
            "generation": predecessor["generation"],
            "manifest_digest": predecessor["manifest_digest"],
            "consumer_sha256": predecessor["consumer_sha256"],
        },
        "stage_name": stage_name,
        "files": files,
        "extra_effects": _v2_capture_effects(
            bound.home, bound.source_commit, stage_name
        ),
        "manager_pre": manager_pre,
        "inverse_actions": ["restore_manager", "restore_files", "discard_generation"],
        "sealed": None,
        "post": None,
        "recovery_count": 0,
        "steps": [
            {
                "sequence": 1,
                "phase": "INTENT",
                "action": "intent_persisted",
                "effect": path,
                "sha256": plan_sha256,
            }
        ],
    }
    return D320CutoverJournalV2.from_payload(payload)


def _v2_transition(
    home: Path,
    previous: D320CutoverJournalV2,
    *,
    lease: _LifecycleLockLease,
    phase: str,
    action: str,
    effect: str,
    digest: str,
    updates: Mapping[str, object] | None = None,
    additional_steps: Sequence[tuple[str, str, str]] = (),
) -> D320CutoverJournalV2:
    payload = previous.payload
    payload.update(updates or {})
    payload["phase"] = phase
    steps = list(payload["steps"])
    sequence = int(payload["sequence"])
    for step_action, step_effect, step_digest in (
        (action, effect, digest),
        *additional_steps,
    ):
        sequence += 1
        steps.append(
            {
                "sequence": sequence,
                "phase": phase,
                "action": step_action,
                "effect": step_effect,
                "sha256": step_digest,
            }
        )
    payload["sequence"] = sequence
    payload["steps"] = steps
    successor = D320CutoverJournalV2.from_payload(payload)
    _v2_store_journal(
        home,
        successor,
        expected_digest=hashlib.sha256(previous.to_bytes()).hexdigest(),
        previous=previous,
        lease=lease,
    )
    return successor


def _v2_record_owner_evidence(
    home: Path,
    journal: D320CutoverJournalV2,
    *,
    lease: _LifecycleLockLease,
    phase: str,
    effect: str,
    digest: str,
) -> D320CutoverJournalV2:
    if any(
        step["phase"] == phase
        and step["action"] == "owner_evidence_readback"
        and step["effect"] == effect
        and step["sha256"] == digest
        for step in journal.payload["steps"]
    ):
        return journal
    return _v2_transition(
        home,
        journal,
        lease=lease,
        phase=phase,
        action="owner_evidence_readback",
        effect=effect,
        digest=digest,
    )


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
                if (
                    not unresolved
                    or index != unresolved[-1]
                    or any(
                        before_steps[item_index]["status"] != "VERIFIED"
                        for item_index in unresolved[:-1]
                    )
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
    _d320_validate_history(history_value, state=state_text, sequence=sequence_value)
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
                parsed = _d320_parse_json(_d320_canonical_json(snapshot, budget=budget))
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
            parsed = _d320_parse_json(_d320_canonical_json(unit_status, budget=budget))
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
            isinstance(step, Mapping) and step["status"] == "VERIFIED" for step in steps
        )
    ):
        return RecoveryClassificationV1("ALL_NEW_VERIFIED", "USER_CUTOVER_VERIFIED", ())
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
        int(step["index"]) for step in reversed(steps) if step["status"] == "VERIFIED"
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
    compatibility_profile: bytes | None = None


@dataclass(slots=True)
class _LifecycleLockLease:
    home: Path
    lock_path: Path
    descriptor: int
    identity: tuple[int, int]
    owner_pid: int
    active: bool = True


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


def _user_runtime_directory() -> Path:
    """Return the same absolute user-runtime path used for manager routing."""

    return _USER_RUNTIME_DIRECTORY_ROOT / str(os.geteuid())


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


def _open_owner_directory(path: Path) -> int:
    if not path.is_absolute() or ".." in path.parts:
        raise _error("runtime_lifecycle_root_hook_effect_unverified")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            child = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child
            info = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid not in {0, os.geteuid()}
                or (
                    stat.S_IMODE(info.st_mode) & 0o022
                    and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX)
                )
            ):
                raise _error("runtime_lifecycle_root_hook_effect_unverified")
        info = os.fstat(descriptor)
        if (
            info.st_uid != _ROOT_HOOK_ABI_UID
            or info.st_gid != _ROOT_HOOK_ABI_GID
            or stat.S_IMODE(info.st_mode) != 0o755
        ):
            raise _error("runtime_lifecycle_root_hook_effect_unverified")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_regular_at(
    parent_fd: int, name: str, *, owner_uid: int, owner_gid: int, mode: int
) -> tuple[bytes, os.stat_result]:
    if not name or "/" in name or name in {".", ".."}:
        raise _error("runtime_lifecycle_root_hook_effect_unverified")
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=parent_fd,
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != owner_uid
            or before.st_gid != owner_gid
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != mode
            or before.st_size <= 0
            or before.st_size > 65536
        ):
            raise _error("runtime_lifecycle_root_hook_effect_unverified")
        chunks = []
        remaining = before.st_size + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            len(raw) != before.st_size
            or before[:7] != after[:7]
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
            or (named.st_dev, named.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise _error("runtime_lifecycle_root_hook_effect_unverified")
        return raw, before
    finally:
        os.close(descriptor)


def _read_root_hook_upgrade_state(
    parent_fd: int, lock_info: os.stat_result
) -> tuple[dict[str, object], os.stat_result]:
    try:
        raw, state_info = _read_regular_at(
            parent_fd,
            _ROOT_HOOK_UPGRADE_STATE,
            owner_uid=_ROOT_HOOK_ABI_UID,
            owner_gid=_ROOT_HOOK_ABI_GID,
            mode=0o644,
        )
        parsed_state = _d320_parse_json(raw)
    except (OSError, TypeError, ValueError) as exc:
        raise _error("runtime_lifecycle_root_hook_upgrade_uncommitted") from exc
    expected_keys = {
        "backup_name",
        "expected_root_state_sha256",
        "generation",
        "manifest_digest",
        "old_receipt",
        "old_target",
        "owner_lock",
        "parent",
        "receipt",
        "schema",
        "stage_name",
        "status",
        "target",
        "transaction_id",
    }
    if not isinstance(parsed_state, dict):
        raise _error("runtime_lifecycle_root_hook_upgrade_uncommitted")
    state = cast(dict[str, object], parsed_state)
    if set(state) != expected_keys:
        raise _error("runtime_lifecycle_root_hook_upgrade_uncommitted")
    parent_info = os.fstat(parent_fd)
    expected_parent = {
        "dev": parent_info.st_dev,
        "gid": parent_info.st_gid,
        "ino": parent_info.st_ino,
        "mode": stat.S_IMODE(parent_info.st_mode),
        "uid": parent_info.st_uid,
    }
    expected_lock = {
        "dev": lock_info.st_dev,
        "gid": lock_info.st_gid,
        "ino": lock_info.st_ino,
        "mode": stat.S_IMODE(lock_info.st_mode),
        "nlink": lock_info.st_nlink,
        "sha256": hashlib.sha256(b"").hexdigest() if lock_info.st_size == 0 else None,
        "size": lock_info.st_size,
        "uid": lock_info.st_uid,
    }
    lock_raw, lock_state = _read_regular_at(
        parent_fd,
        ".root-hook-abi-owner.lock",
        owner_uid=_ROOT_HOOK_ABI_UID,
        owner_gid=_ROOT_HOOK_ABI_GID,
        mode=0o644,
    )
    expected_lock["sha256"] = hashlib.sha256(lock_raw).hexdigest()
    if (
        state.get("schema") != "RootHookAbiUpgradeStateV1"
        or state.get("status") != "committed"
        or not isinstance(state.get("transaction_id"), str)
        or re.fullmatch(r"[0-9a-f]{32}", state["transaction_id"]) is None
        or not isinstance(state.get("expected_root_state_sha256"), str)
        or re.fullmatch(_SHA256_HEX_PATTERN, state["expected_root_state_sha256"])
        is None
        or state.get("parent") != expected_parent
        or state.get("owner_lock") != expected_lock
        or state_info.st_uid != _ROOT_HOOK_ABI_UID
        or state_info.st_gid != _ROOT_HOOK_ABI_GID
        or state_info.st_nlink != 1
        or stat.S_IMODE(state_info.st_mode) != 0o644
        or (lock_state.st_dev, lock_state.st_ino)
        != (lock_info.st_dev, lock_info.st_ino)
    ):
        raise _error("runtime_lifecycle_root_hook_upgrade_uncommitted")
    parsed_old_target = state["old_target"]
    if not isinstance(parsed_old_target, dict):
        raise _error("runtime_lifecycle_root_hook_upgrade_uncommitted")
    old_target = cast(dict[str, object], parsed_old_target)
    backup_name = state["backup_name"]
    if old_target == {"present": False}:
        if backup_name is not None:
            raise _error("runtime_lifecycle_root_hook_upgrade_uncommitted")
    else:
        if (
            set(old_target) != {"dev", "gid", "ino", "mode", "present", "uid"}
            or old_target.get("present") is not True
            or any(
                type(old_target.get(field)) is not int
                for field in ("dev", "gid", "ino", "mode", "uid")
            )
        ):
            raise _error("runtime_lifecycle_root_hook_upgrade_uncommitted")
        if (
            not isinstance(backup_name, str)
            or re.fullmatch(r"\.v1\.previous-[0-9a-f]{32}", backup_name) is None
        ):
            raise _error("runtime_lifecycle_root_hook_upgrade_uncommitted")
        try:
            backup_info = os.stat(backup_name, dir_fd=parent_fd, follow_symlinks=False)
        except (OSError, TypeError) as exc:
            raise _error("runtime_lifecycle_root_hook_upgrade_uncommitted") from exc
        if (
            not stat.S_ISDIR(backup_info.st_mode)
            or backup_info.st_uid != old_target["uid"]
            or backup_info.st_gid != old_target["gid"]
            or stat.S_IMODE(backup_info.st_mode) != old_target["mode"]
            or (backup_info.st_dev, backup_info.st_ino)
            != (old_target["dev"], old_target["ino"])
        ):
            raise _error("runtime_lifecycle_root_hook_upgrade_uncommitted")
    parsed_old_receipt = state["old_receipt"]
    if not isinstance(parsed_old_receipt, dict):
        raise _error("runtime_lifecycle_root_hook_upgrade_uncommitted")
    old_receipt = cast(dict[str, object], parsed_old_receipt)
    old_receipt_fields = {
        "dev",
        "gid",
        "ino",
        "mode",
        "nlink",
        "present",
        "sha256",
        "size",
        "uid",
    }
    if old_receipt != {"present": False} and (
        set(old_receipt) != old_receipt_fields
        or old_receipt.get("present") is not True
        or any(
            type(old_receipt.get(field)) is not int
            for field in old_receipt_fields - {"sha256", "present"}
        )
        or not isinstance(old_receipt.get("sha256"), str)
        or re.fullmatch(_SHA256_HEX_PATTERN, old_receipt["sha256"]) is None
    ):
        raise _error("runtime_lifecycle_root_hook_upgrade_uncommitted")
    for name in ("stage_name", "backup_name"):
        parsed_value = state[name]
        if parsed_value is None:
            continue
        if (
            not isinstance(parsed_value, str)
            or re.fullmatch(r"\.v1\.(?:stage|previous)-[0-9a-f]{32}", parsed_value)
            is None
        ):
            raise _error("runtime_lifecycle_root_hook_upgrade_uncommitted")
    for name in ("target", "receipt"):
        value = state[name]
        expected = {"dev", "gid", "ino", "mode", "nlink", "size", "uid"}
        if name == "target":
            expected -= {"nlink", "size"}
        else:
            expected.add("sha256")
        if set(value) != expected:
            raise _error("runtime_lifecycle_root_hook_upgrade_uncommitted")
        if any(type(value.get(field)) is not int for field in expected - {"sha256"}):
            raise _error("runtime_lifecycle_root_hook_upgrade_uncommitted")
        if name == "receipt" and (
            not isinstance(value.get("sha256"), str)
            or re.fullmatch(_SHA256_HEX_PATTERN, value["sha256"]) is None
        ):
            raise _error("runtime_lifecycle_root_hook_upgrade_uncommitted")
    if (
        not isinstance(state.get("generation"), str)
        or re.fullmatch(r"[0-9a-f]{40}", state["generation"]) is None
        or not isinstance(state.get("manifest_digest"), str)
        or re.fullmatch(_ROOT_HOOK_MANIFEST_DIGEST_PATTERN, state["manifest_digest"])
        is None
    ):
        raise _error("runtime_lifecycle_root_hook_upgrade_uncommitted")
    return state, state_info


def _verify_root_hook_effect_receipt(
    *, generation: str, manifest_digest: str, hold_lock: bool = False
) -> str | tuple[str, int]:
    parent_fd = _open_owner_directory(_ROOT_HOOK_ABI_PARENT)
    parent_info = os.fstat(parent_fd)
    lock_fd = -1
    target_fd = -1
    try:
        lock_fd = os.open(
            ".root-hook-abi-owner.lock",
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_fd,
        )
        lock_info = os.fstat(lock_fd)
        if (
            not stat.S_ISREG(lock_info.st_mode)
            or lock_info.st_uid != _ROOT_HOOK_ABI_UID
            or lock_info.st_gid != _ROOT_HOOK_ABI_GID
            or lock_info.st_nlink != 1
            or stat.S_IMODE(lock_info.st_mode) != 0o644
        ):
            raise _error("runtime_lifecycle_root_hook_effect_unverified")
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except OSError as exc:
            raise _error("runtime_lifecycle_root_hook_effect_busy") from exc
        lock_info = os.fstat(lock_fd)
        upgrade_state, upgrade_info = _read_root_hook_upgrade_state(
            parent_fd, lock_info
        )
        raw, receipt_info = _read_regular_at(
            parent_fd,
            _ROOT_HOOK_EFFECT_RECEIPT,
            owner_uid=_ROOT_HOOK_ABI_UID,
            owner_gid=_ROOT_HOOK_ABI_GID,
            mode=0o644,
        )
        try:
            receipt = _d320_parse_json(raw)
        except (TypeError, ValueError) as exc:
            raise _error("runtime_lifecycle_root_hook_effect_unverified") from exc
        if not isinstance(receipt, dict):
            raise _error("runtime_lifecycle_root_hook_effect_unverified")
        receipt = cast(dict[str, object], receipt)
        expected_keys = {
            "effect",
            "files",
            "generation",
            "issued_at_unix_ns",
            "manifest_digest",
            "owner",
            "root_uid",
            "schema_version",
            "source_uid",
            "target",
        }
        if (
            set(receipt) != expected_keys
            or receipt.get("schema_version") != 1
            or receipt.get("owner") != "root_hook_abi_v1"
            or receipt.get("effect") != "root_hook_abi_verified_present"
            or receipt.get("target") != str(_ROOT_HOOK_ABI_PARENT / "v1")
            or receipt.get("generation") != generation
            or receipt.get("manifest_digest") != manifest_digest
            or receipt.get("root_uid") != _ROOT_HOOK_ABI_UID
            or receipt.get("source_uid") != os.geteuid()
            or type(receipt.get("issued_at_unix_ns")) is not int
        ):
            raise _error("runtime_lifecycle_root_hook_effect_unverified")
        if (
            upgrade_state["generation"] != generation
            or upgrade_state["manifest_digest"] != manifest_digest
        ):
            raise _error("runtime_lifecycle_root_hook_effect_unverified")
        issued = receipt["issued_at_unix_ns"]
        now = time.time_ns()
        if issued > now or now >= issued + _OWNER_RECEIPT_FRESHNESS_NS:
            raise _error("runtime_lifecycle_owner_receipt_expired")
        target_fd = os.open(
            "v1",
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_fd,
        )
        target_info = os.fstat(target_fd)
        if (
            target_info.st_uid != _ROOT_HOOK_ABI_UID
            or target_info.st_gid != _ROOT_HOOK_ABI_GID
            or stat.S_IMODE(target_info.st_mode) != 0o755
        ):
            raise _error("runtime_lifecycle_root_hook_effect_unverified")
        receipt_identity = upgrade_state["receipt"]
        target_identity = upgrade_state["target"]
        state_name_info = os.stat(
            _ROOT_HOOK_UPGRADE_STATE, dir_fd=parent_fd, follow_symlinks=False
        )
        if (
            (state_name_info.st_dev, state_name_info.st_ino)
            != (upgrade_info.st_dev, upgrade_info.st_ino)
            or (target_info.st_dev, target_info.st_ino)
            != (target_identity["dev"], target_identity["ino"])
            or any(
                getattr(target_info, field) != target_identity[key]
                for field, key in (
                    ("st_dev", "dev"),
                    ("st_ino", "ino"),
                    ("st_uid", "uid"),
                    ("st_gid", "gid"),
                )
            )
            or stat.S_IMODE(target_info.st_mode) != target_identity["mode"]
            or (receipt_info.st_dev, receipt_info.st_ino)
            != (receipt_identity["dev"], receipt_identity["ino"])
            or receipt_info.st_uid != receipt_identity["uid"]
            or receipt_info.st_gid != receipt_identity["gid"]
            or stat.S_IMODE(receipt_info.st_mode) != receipt_identity["mode"]
            or receipt_info.st_nlink != receipt_identity["nlink"]
            or receipt_info.st_size != receipt_identity["size"]
            or hashlib.sha256(raw).hexdigest() != receipt_identity["sha256"]
        ):
            raise _error("runtime_lifecycle_root_hook_effect_unverified")
        files = receipt.get("files")
        if not isinstance(files, dict) or set(files) != {
            "launcher",
            "hook_session_pin_store.py",
            "hook_abi_v1_core.py",
            *[
                name
                for name in files
                if isinstance(name, str)
                and re.fullmatch(r"allowlists/[0-9a-f]{64}\.json", name)
            ],
        }:
            raise _error("runtime_lifecycle_root_hook_effect_unverified")
        if len(files) != 4:
            raise _error("runtime_lifecycle_root_hook_effect_unverified")
        allowlist_names = {
            name.split("/", 1)[1]
            for name in files
            if isinstance(name, str) and name.startswith("allowlists/")
        }
        top_level_names = {
            name for name in files if isinstance(name, str) and "/" not in name
        }
        if set(os.listdir(target_fd)) != {*top_level_names, "allowlists"}:
            raise _error("runtime_lifecycle_root_hook_effect_unverified")
        allowlist_fd = os.open(
            "allowlists",
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=target_fd,
        )
        try:
            allowlist_info = os.fstat(allowlist_fd)
            if (
                allowlist_info.st_uid != _ROOT_HOOK_ABI_UID
                or allowlist_info.st_gid != _ROOT_HOOK_ABI_GID
                or stat.S_IMODE(allowlist_info.st_mode) != 0o755
                or set(os.listdir(allowlist_fd)) != allowlist_names
            ):
                raise _error("runtime_lifecycle_root_hook_effect_unverified")
        finally:
            os.close(allowlist_fd)
        for name, member in files.items():
            if (
                not isinstance(member, dict)
                or set(member) != {"mode", "nlink", "sha256", "size"}
                or any(
                    type(member[field]) is not int
                    for field in ("mode", "nlink", "size")
                )
            ):
                raise _error("runtime_lifecycle_root_hook_effect_unverified")
            directory_fd = target_fd
            member_name = name
            if name.startswith("allowlists/"):
                directory_fd = os.open(
                    "allowlists",
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=target_fd,
                )
                member_name = name.split("/", 1)[1]
            try:
                expected_mode = 0o755 if name == "launcher" else 0o644
                content, info = _read_regular_at(
                    directory_fd,
                    member_name,
                    owner_uid=_ROOT_HOOK_ABI_UID,
                    owner_gid=_ROOT_HOOK_ABI_GID,
                    mode=expected_mode,
                )
            finally:
                if directory_fd != target_fd:
                    os.close(directory_fd)
            if (
                member.get("mode") != expected_mode
                or member.get("nlink") != 1
                or member.get("size") != len(content)
                or member.get("sha256") != hashlib.sha256(content).hexdigest()
                or info.st_nlink != member.get("nlink")
            ):
                raise _error("runtime_lifecycle_root_hook_effect_unverified")
        final_parent_fd = _open_owner_directory(_ROOT_HOOK_ABI_PARENT)
        try:
            final_parent_info = os.fstat(final_parent_fd)
            final_lock_raw, final_lock_info = _read_regular_at(
                final_parent_fd,
                ".root-hook-abi-owner.lock",
                owner_uid=_ROOT_HOOK_ABI_UID,
                owner_gid=_ROOT_HOOK_ABI_GID,
                mode=0o644,
            )
            final_target_info = os.stat(
                "v1", dir_fd=final_parent_fd, follow_symlinks=False
            )
            final_receipt_raw, final_receipt_info = _read_regular_at(
                final_parent_fd,
                _ROOT_HOOK_EFFECT_RECEIPT,
                owner_uid=_ROOT_HOOK_ABI_UID,
                owner_gid=_ROOT_HOOK_ABI_GID,
                mode=0o644,
            )
            final_state_raw, final_state_info = _read_regular_at(
                final_parent_fd,
                _ROOT_HOOK_UPGRADE_STATE,
                owner_uid=_ROOT_HOOK_ABI_UID,
                owner_gid=_ROOT_HOOK_ABI_GID,
                mode=0o644,
            )
            final_state = _d320_parse_json(final_state_raw)
        finally:
            os.close(final_parent_fd)
        if (
            (final_parent_info.st_dev, final_parent_info.st_ino)
            != (parent_info.st_dev, parent_info.st_ino)
            or final_parent_info.st_uid != parent_info.st_uid
            or final_parent_info.st_gid != parent_info.st_gid
            or stat.S_IMODE(final_parent_info.st_mode)
            != stat.S_IMODE(parent_info.st_mode)
            or (final_lock_info.st_dev, final_lock_info.st_ino)
            != (lock_info.st_dev, lock_info.st_ino)
            or hashlib.sha256(final_lock_raw).hexdigest()
            != upgrade_state["owner_lock"]["sha256"]
            or (final_target_info.st_dev, final_target_info.st_ino)
            != (target_info.st_dev, target_info.st_ino)
            or not stat.S_ISDIR(final_target_info.st_mode)
            or final_target_info.st_uid != target_info.st_uid
            or final_target_info.st_gid != target_info.st_gid
            or stat.S_IMODE(final_target_info.st_mode)
            != stat.S_IMODE(target_info.st_mode)
            or final_target_info.st_mtime_ns != target_info.st_mtime_ns
            or final_target_info.st_ctime_ns != target_info.st_ctime_ns
            or (final_receipt_info.st_dev, final_receipt_info.st_ino)
            != (receipt_info.st_dev, receipt_info.st_ino)
            or final_receipt_raw != raw
            or final_receipt_info.st_mtime_ns != receipt_info.st_mtime_ns
            or final_receipt_info.st_ctime_ns != receipt_info.st_ctime_ns
            or (final_state_info.st_dev, final_state_info.st_ino)
            != (upgrade_info.st_dev, upgrade_info.st_ino)
            or final_state != upgrade_state
            or final_state_info.st_mtime_ns != upgrade_info.st_mtime_ns
            or final_state_info.st_ctime_ns != upgrade_info.st_ctime_ns
        ):
            raise _error("runtime_lifecycle_root_hook_upgrade_uncommitted")
        digest = hashlib.sha256(raw).hexdigest()
        if hold_lock:
            result_fd = lock_fd
            lock_fd = -1
            return digest, result_fd
        return digest
    except RuntimeLifecycleError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise _error("runtime_lifecycle_root_hook_effect_unverified") from exc
    finally:
        if target_fd >= 0:
            os.close(target_fd)
        if lock_fd >= 0:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
        os.close(parent_fd)


def _release_root_hook_effect_lock(lock_fd: int) -> None:
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
    finally:
        os.close(lock_fd)


def _verify_plugin_release_effect_receipt(
    *, home: Path, generation: str, manifest_digest: str
) -> str:
    state_root = home / ".local/state/codex-master-mcp/hive"
    plugin = home / "plugins/the-hive"
    receipt_path = state_root / _PLUGIN_EFFECT_RECEIPT
    target = plugin / "release-binding.json"
    marketplace_path = home / ".agents/plugins/marketplace.json"
    try:
        _bound_path_from_home(home, state_root)
        _bound_path_from_home(home, plugin)
        raw = _regular_bytes(receipt_path, maximum=65536, mode=0o600)
        descriptor = _regular_bytes(target, maximum=65536, mode=0o644)
        marketplace = _regular_bytes(marketplace_path, maximum=65536, mode=0o644)
        if raw is None or descriptor is None or marketplace is None:
            raise _error("runtime_lifecycle_plugin_effect_unverified")
        receipt = _d320_parse_json(raw)
    except RuntimeLifecycleError:
        raise
    except (D320CutoverJournalError, OSError, TypeError, ValueError) as exc:
        raise _error("runtime_lifecycle_plugin_effect_unverified") from exc
    expected_keys = {
        "descriptor_sha256",
        "effect",
        "generation",
        "issued_at_unix_ns",
        "manifest_digest",
        "marketplace_sha256",
        "owner",
        "plugin_identity",
        "schema_version",
        "target",
        "target_identity",
    }
    if (
        not isinstance(receipt, dict)
        or set(receipt) != expected_keys
        or receipt.get("schema_version") != 1
        or receipt.get("owner") != "plugin_release_publisher"
        or receipt.get("effect") != "plugin_release_descriptor_verified_present"
        or receipt.get("target") != "plugins/the-hive/release-binding.json"
        or receipt.get("generation") != generation
        or receipt.get("manifest_digest") != manifest_digest
        or receipt.get("descriptor_sha256")
        != "sha256:" + hashlib.sha256(descriptor).hexdigest()
        or receipt.get("marketplace_sha256") != hashlib.sha256(marketplace).hexdigest()
        or type(receipt.get("issued_at_unix_ns")) is not int
    ):
        raise _error("runtime_lifecycle_plugin_effect_unverified")
    issued = receipt["issued_at_unix_ns"]
    now = time.time_ns()
    if issued > now or now >= issued + _OWNER_RECEIPT_FRESHNESS_NS:
        raise _error("runtime_lifecycle_owner_receipt_expired")
    try:
        plugin_info = plugin.lstat()
        target_info = target.lstat()
        receipt_info = receipt_path.lstat()
        marketplace_recheck = _regular_bytes(
            marketplace_path, maximum=65536, mode=0o644
        )
        descriptor_recheck = _regular_bytes(target, maximum=65536, mode=0o644)
        receipt_recheck = _regular_bytes(receipt_path, maximum=65536, mode=0o600)
    except OSError as exc:
        raise _error("runtime_lifecycle_plugin_effect_unverified") from exc
    plugin_identity = receipt.get("plugin_identity")
    target_identity = receipt.get("target_identity")
    if (
        not stat.S_ISDIR(plugin_info.st_mode)
        or plugin_info.st_uid != os.geteuid()
        or plugin_identity != {"dev": plugin_info.st_dev, "ino": plugin_info.st_ino}
        or not stat.S_ISREG(target_info.st_mode)
        or target_info.st_uid != os.geteuid()
        or target_info.st_nlink != 1
        or stat.S_IMODE(target_info.st_mode) != 0o644
        or target_identity
        != {
            "dev": target_info.st_dev,
            "gid": target_info.st_gid,
            "ino": target_info.st_ino,
            "mode": stat.S_IMODE(target_info.st_mode),
            "nlink": target_info.st_nlink,
            "size": target_info.st_size,
            "uid": target_info.st_uid,
        }
        or descriptor_recheck != descriptor
        or marketplace_recheck != marketplace
        or receipt_recheck != raw
        or not stat.S_ISREG(receipt_info.st_mode)
        or receipt_info.st_uid != os.geteuid()
        or receipt_info.st_nlink != 1
        or stat.S_IMODE(receipt_info.st_mode) != 0o600
    ):
        raise _error("runtime_lifecycle_plugin_effect_unverified")
    return hashlib.sha256(raw).hexdigest()


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
                or layout_root != release_root / "generations" / source_commit
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
    canonical_state = Path(home_text) / ".local" / "state" / "codex-master-mcp"
    canonical_state_text = _canary_path_text(canonical_state)
    user_runtime_text = _canary_path_text(_user_runtime_directory())
    replacements = {
        _HOURLY_PROBE_MANAGED_RUNTIME_DIRECTORY: f"RuntimeDirectory={unit_stem}",
        _HOURLY_PROBE_MANAGED_RUNTIME_DIRECTORY_MODE: (
            _HOURLY_PROBE_MANAGED_RUNTIME_DIRECTORY_MODE
        ),
        _HOURLY_PROBE_RUNTIME_ROOT_BINDING: (
            f"BindReadOnlyPaths={release}:{release}:norbind"
        ),
        _HOURLY_PROBE_PROTECTED_HOME_BUS_BINDING: (
            f"BindReadOnlyPaths={user_runtime_text}/bus:{user_runtime_text}/bus:norbind"
        ),
        _HOURLY_PROBE_PROTECTED_HOME_MANAGER_BINDING: (
            "BindReadOnlyPaths="
            f"{user_runtime_text}/systemd/private:"
            f"{user_runtime_text}/systemd/private:norbind"
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
        else:
            properties.append(directive)
    if not type_seen or not exec_seen or seen != set(replacements):
        raise _error("runtime_canary_sandbox_invalid")
    properties.extend(
        ("RemainAfterExit=yes", "StandardOutput=null", "StandardError=null")
    )
    return _CanaryUnitBinding(
        name=f"{unit_stem}.service",
        description=f"The Hive runtime canary {nonce}",
        home=home,
        properties=tuple(properties),
        command=(
            "/usr/bin/bash",
            os.fspath(
                image.release_root
                / "generations"
                / image.generation
                / "bin"
                / "the-hive-hive-hourly-probe"
            ),
            release,
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
    profile_path = (
        repository
        / "src"
        / "the_hive"
        / "markdown"
        / "runtime-release-compatibility-v1.json"
    )
    compatibility_profile = _regular_bytes(profile_path, maximum=64 * 1024, mode=0o644)
    source_digests = tuple((path, _source_digest(path)) for path in sources)
    if compatibility_profile is not None:
        source_digests += (
            (profile_path, hashlib.sha256(compatibility_profile).hexdigest()),
        )
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
        compatibility_profile=compatibility_profile,
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


def _v2_verify_installed_outputs(home: Path, sealed: Mapping[str, object]) -> None:
    outputs = sealed.get("output_sha256")
    if not isinstance(outputs, Mapping):
        raise _error("runtime_lifecycle_journal_invalid")
    paths = {
        "mcp_launcher": home / ".local" / "lib" / "the-hive-runtime" / "the-hive-mcp",
        "hourly_service": home / ".config" / "systemd" / "user" / _NEW_SERVICE,
        "hourly_timer": home / ".config" / "systemd" / "user" / _NEW_TIMER,
        "pricing_launcher": home / ".local" / "bin" / _PRICING_LAUNCHER,
        "pricing_service": home / ".config" / "systemd" / "user" / _PRICING_UNITS[0],
        "pricing_timer": home / ".config" / "systemd" / "user" / _PRICING_UNITS[1],
        "legacy_launcher": home
        / ".local"
        / "libexec"
        / "codex_master_hive_hourly_probe.py",
    }
    for name, path in paths.items():
        content = _regular_bytes(
            path,
            maximum=_MAX_UNIT_BYTES,
            mode=0o644 if name.endswith(("service", "timer")) else 0o755,
        )
        if content is None or hashlib.sha256(content).hexdigest() != outputs[name]:
            raise _error("runtime_lifecycle_installed_output_changed")


def _v2_capture_post(
    home: Path, source_commit: str, stage_name: str, bound: _BoundCutover
) -> dict[str, object]:
    files: list[dict[str, object]] = []
    for path, _old_content, mode in bound.files:
        content = _regular_bytes(
            path,
            maximum=(
                _MAX_HEALTH_BYTES
                if path.name == ".the-hive-release-pointers.json"
                else (
                    _MAX_OBSERVATION_BYTES
                    if path.name == _OBSERVATION_NAME
                    else _MAX_UNIT_BYTES
                )
            ),
            mode=mode,
        )
        if content is None:
            files.append(
                {
                    "name": path.name,
                    "path": str(path),
                    "present": False,
                    "bytes_b64": None,
                    "sha256": None,
                    "dev": None,
                    "ino": None,
                    "uid": None,
                    "gid": None,
                    "mode": None,
                    "nlink": None,
                    "size": None,
                }
            )
            continue
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.geteuid()
        ):
            raise _error("runtime_lifecycle_observation_changed")
        files.append(
            {
                "name": path.name,
                "path": str(path),
                "present": True,
                "bytes_b64": base64.b64encode(content).decode("ascii"),
                "sha256": hashlib.sha256(content).hexdigest(),
                "dev": info.st_dev,
                "ino": info.st_ino,
                "uid": info.st_uid,
                "gid": info.st_gid,
                "mode": stat.S_IMODE(info.st_mode),
                "nlink": info.st_nlink,
                "size": len(content),
            }
        )
    if bound.source_commit != source_commit:
        raise _error("runtime_lifecycle_source_changed")
    return {
        "files": files,
        "extra_effects": _v2_capture_effects(home, source_commit, stage_name),
        "manager_states": {name: dict(state) for name, state in bound.states},
    }


def _v2_capture_managed_file(path: Path, mode: int) -> dict[str, object]:
    maximum = (
        _MAX_HEALTH_BYTES
        if path.name == ".the-hive-release-pointers.json"
        else (
            _MAX_OBSERVATION_BYTES
            if path.name == _OBSERVATION_NAME
            else _MAX_UNIT_BYTES
        )
    )
    content = _regular_bytes(path, maximum=maximum, mode=mode)
    if content is None:
        return {
            "name": path.name,
            "path": str(path),
            "present": False,
            "bytes_b64": None,
            "sha256": None,
            "dev": None,
            "ino": None,
            "uid": None,
            "gid": None,
            "mode": None,
            "nlink": None,
            "size": None,
        }
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != os.geteuid()
    ):
        raise _error("runtime_lifecycle_effect_identity_invalid")
    return {
        "name": path.name,
        "path": str(path),
        "present": True,
        "bytes_b64": base64.b64encode(content).decode("ascii"),
        "sha256": hashlib.sha256(content).hexdigest(),
        "dev": info.st_dev,
        "ino": info.st_ino,
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": stat.S_IMODE(info.st_mode),
        "nlink": info.st_nlink,
        "size": len(content),
    }


def _v2_post_matches(
    current: Mapping[str, object], recorded: Mapping[str, object]
) -> bool:
    """Compare all post-state except the journal inode, which this write replaces."""

    current_copy = dict(current)
    recorded_copy = dict(recorded)
    # The journal is an effect, not one of the managed input/output files.
    current_copy["extra_effects"] = [
        item for item in current_copy["extra_effects"] if item["kind"] != "journal"
    ]
    recorded_copy["extra_effects"] = [
        item for item in recorded_copy["extra_effects"] if item["kind"] != "journal"
    ]
    return current_copy == recorded_copy


def _v2_phase_plan(
    *, home: Path, journal: D320CutoverJournalV2, systemctl: Systemctl
) -> dict[str, object]:
    payload = journal.payload
    phase = str(payload["phase"])
    next_phase = {
        "INTENT": "install",
        "INSTALLED": "activate",
        "ACTIVATED": "observe",
        "OBSERVED": "commit",
    }.get(phase)
    if next_phase is None:
        return {
            "status": "runtime_lifecycle_plan_blocked",
            "reason_codes": ["runtime_lifecycle_recovery_required"],
            "journal_phase": phase,
            "raw_output": "not_returned",
        }
    try:
        target = home.lstat()
        binding = payload["target"]
        if (
            str(home.resolve(strict=True)) != binding["realpath"]
            or (target.st_dev, target.st_ino, target.st_uid, target.st_gid)
            != (binding["dev"], binding["ino"], binding["uid"], binding["gid"])
            or stat.S_IMODE(target.st_mode) != binding["mode"]
        ):
            raise _error("runtime_lifecycle_target_changed")
        bound = _bind_systemd_states(_bind_cutover_inputs(home), systemctl)
        if (
            bound.source_commit != payload["source"]["commit"]
            or bound.source_tree_digest != payload["source"]["tree_sha256"]
        ):
            raise _error("runtime_lifecycle_source_changed")
        if (
            phase in {"INTENT", "INSTALLED"}
            and dict(bound.states) != payload["manager_pre"]
        ):
            raise _error("runtime_lifecycle_manager_state_changed")
        if phase == "INTENT":
            _revalidate_v2_predecessor(
                bound.release_root, payload["plan"]["predecessor"]
            )
            effects = _v2_capture_effects(
                home, payload["source"]["commit"], payload["stage_name"]
            )
            stage = next(item for item in effects if item["kind"] == "stage")
            generation = next(item for item in effects if item["kind"] == "generation")
            if stage["present"] or generation["present"]:
                raise _error("runtime_lifecycle_recovery_required")
        if phase in {"INSTALLED", "ACTIVATED", "OBSERVED"}:
            sealed = payload["sealed"]
            identity = _runtime_identity(bound.release_root)
            if (
                not isinstance(sealed, Mapping)
                or not isinstance(identity, Mapping)
                or identity.get("generation") != sealed["generation"]
                or identity.get("manifest_digest") != sealed["manifest_digest"]
            ):
                raise _error("runtime_lifecycle_installed_runtime_changed")
            _v2_verify_installed_outputs(home, sealed)
        if phase == "ACTIVATED":
            states = dict(bound.states)
            timer = states[_NEW_TIMER]
            legacy_timer = states[_LEGACY_TIMER]
            legacy_service = states[_LEGACY_SERVICE]
            if (
                timer.get("UnitFileState") != "enabled"
                or timer.get("ActiveState") != "active"
                or legacy_timer.get("UnitFileState") != "disabled"
                or legacy_timer.get("ActiveState") != "inactive"
                or legacy_service.get("ActiveState") != "inactive"
            ):
                raise _error("runtime_lifecycle_manager_state_changed")
        if phase == "OBSERVED":
            observed = _v2_capture_post(
                home, payload["source"]["commit"], payload["stage_name"], bound
            )
            if not _v2_post_matches(observed, payload["post"]):
                raise _error("runtime_lifecycle_observation_changed")
    except RuntimeLifecycleError as exc:
        return {
            "status": "runtime_lifecycle_plan_blocked",
            "reason_codes": [str(exc)],
            "journal_phase": phase,
            "raw_output": "not_returned",
        }
    return {
        "status": "runtime_lifecycle_plan_ready",
        "plan": payload["plan"],
        "plan_sha256": payload["plan_sha256"],
        "reason_codes": [],
        "journal_phase": phase,
        "next_phase": next_phase,
        "raw_output": "not_returned",
    }


def _v2_qualification_record_reason(plan: Mapping[str, object]) -> str | None:
    qualification = plan.get("qualification")
    if not isinstance(qualification, Mapping):
        return "runtime_lifecycle_qualification_record_invalid"
    record = _read_canary_qualification_record(_canary_runtime_root())
    if record is None:
        return "runtime_lifecycle_qualification_record_missing"
    issued_at = record.get("issued_at_unix_ns")
    if (
        type(issued_at) is not int
        or issued_at != qualification.get("issued_at_unix_ns")
        or qualification.get("sha256")
        != hashlib.sha256(_d320_canonical_json(dict(record))).hexdigest()
    ):
        return "runtime_lifecycle_qualification_record_changed"
    now = time.time_ns()
    if issued_at > now:
        return "runtime_lifecycle_qualification_record_invalid"
    if now >= issued_at + _OWNER_RECEIPT_FRESHNESS_NS:
        return "runtime_lifecycle_qualification_record_expired"
    if record.get("status") != "qualified":
        return "runtime_lifecycle_qualification_record_unqualified"
    criteria = record.get("criteria")
    if not isinstance(criteria, Mapping) or any(
        criteria.get(name) != "pass"
        for name in (
            "client_probe",
            "client_compatibility",
            "manager_api_contract",
            "runtime_canary",
            "runtime_features",
        )
    ):
        return "runtime_lifecycle_qualification_record_unverified"
    bindings = record.get("bindings")
    source = plan.get("source")
    compatibility = plan.get("compatibility")
    predecessor = plan.get("predecessor")
    if not all(
        isinstance(item, Mapping)
        for item in (bindings, source, compatibility, predecessor)
    ):
        return "runtime_lifecycle_qualification_record_changed"
    if compatibility.get("status") != "qualified":
        return "runtime_lifecycle_qualification_record_changed"
    expected_predecessor = {
        key: predecessor.get(key)
        for key in ("consumer_sha256", "generation", "manifest_digest")
    }
    if (
        bindings.get("source_commit") != source.get("commit")
        or bindings.get("source_tree_sha256") != source.get("tree_sha256")
        or bindings.get("profile_sha256") != compatibility.get("sha256")
        or bindings.get("candidate_generation") != source.get("commit")
        or bindings.get("predecessor") != expected_predecessor
        or bindings.get("target") != plan.get("target")
        or bindings.get("manager_states_sha256")
        != _manager_states_digest(plan.get("manager_states"))
        or bindings.get("manager_api_contract") != _manager_api_contract_snapshot()
    ):
        return "runtime_lifecycle_qualification_record_changed"
    candidate_manifest = bindings.get("candidate_manifest_digest")
    planned_manifest = plan.get("output_manifest_digest")
    if planned_manifest != "pending" and candidate_manifest != planned_manifest:
        return "runtime_lifecycle_qualification_record_changed"
    client = bindings.get("client")
    current_client_digest = _canonical_codex_client_digest()
    if (
        not isinstance(client, Mapping)
        or current_client_digest is None
        or client.get("artifact_sha256") != current_client_digest
    ):
        return "runtime_lifecycle_qualification_record_changed"
    return None


def plan(*, home: Path, systemctl: Systemctl | None = None) -> dict[str, object]:
    """Return a deterministic, read-only binding of the currently known inputs."""

    try:
        existing = _v2_load_journal(home)
        if existing is not None and existing.payload["phase"] not in {
            "COMMITTED",
            "ROLLED_BACK",
        }:
            qualification_reason = _v2_qualification_record_reason(
                existing.payload["plan"]
            )
            if qualification_reason is not None:
                return {
                    "status": "runtime_lifecycle_plan_blocked",
                    "reason_codes": [qualification_reason],
                    "journal_phase": existing.payload["phase"],
                    "raw_output": "not_returned",
                }
            return _v2_phase_plan(
                home=home,
                journal=existing,
                systemctl=systemctl or _systemctl_default,
            )
        bound = _bind_systemd_states(
            _bind_cutover_inputs(home), systemctl or _systemctl_default
        )
        target = _target_binding(home)
        predecessor = _runtime_identity(bound.release_root)
        reason_codes: list[str] = []
        compatibility: dict[str, object] = {
            "status": "missing",
            "sha256": None,
        }
        if (
            not isinstance(predecessor, Mapping)
            or not isinstance(predecessor.get("generation"), str)
            or not isinstance(predecessor.get("manifest_digest"), str)
            or predecessor.get("consumer_pin") is not True
            or not isinstance(predecessor.get("consumer_sha256"), str)
        ):
            reason_codes.append("runtime_lifecycle_predecessor_missing")
        if bound.compatibility_profile is None:
            reason_codes.append("runtime_release_compatibility_profile_missing")
        else:
            try:
                from the_hive.runtime_layout import (
                    validate_runtime_release_compatibility_profile,
                )

                validated_profile = validate_runtime_release_compatibility_profile(
                    bound.compatibility_profile
                )
            except (ValueError, RuntimeLifecycleError):
                reason_codes.append("runtime_release_compatibility_profile_invalid")
            else:
                compatibility = {
                    "status": (
                        "qualified"
                        if validated_profile.get("schema_version") == 2
                        and validated_profile.get("status") == "structural_requirements"
                        else "present_unvalidated"
                    ),
                    "sha256": hashlib.sha256(bound.compatibility_profile).hexdigest(),
                }
                if compatibility["status"] != "qualified":
                    reason_codes.append(
                        "runtime_release_compatibility_profile_unvalidated"
                    )
        qualification_root = _canary_runtime_root()
        qualification_record = _read_canary_qualification_record(qualification_root)
        qualification: dict[str, object]
        if qualification_record is None:
            qualification = {"status": "missing"}
            reason_codes.append("runtime_lifecycle_qualification_record_missing")
        else:
            issued_at = qualification_record["issued_at_unix_ns"]
            qualification = {
                "status": qualification_record["status"],
                "issued_at_unix_ns": issued_at,
                "sha256": hashlib.sha256(
                    _d320_canonical_json(dict(qualification_record))
                ).hexdigest(),
            }
            qualification_plan = {
                "source": {
                    "commit": bound.source_commit,
                    "tree_sha256": bound.source_tree_digest,
                },
                "compatibility": compatibility,
                "predecessor": dict(predecessor)
                if isinstance(predecessor, Mapping)
                else None,
                "target": target,
                "manager_states": dict(bound.states),
                "output_manifest_digest": "pending",
                "qualification": qualification,
            }
            qualification_reason = _v2_qualification_record_reason(qualification_plan)
            if qualification_reason is not None:
                reason_codes.append(qualification_reason)
        snapshots: list[dict[str, object]] = []
        for path, content, _mode in bound.files:
            if content is None:
                fields: dict[str, object] = {"sha256": None, "mode": None}
            else:
                info = path.lstat()
                fields = {
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "mode": stat.S_IMODE(info.st_mode),
                    "dev": info.st_dev,
                    "ino": info.st_ino,
                    "uid": info.st_uid,
                    "gid": info.st_gid,
                    "nlink": info.st_nlink,
                }
            snapshots.append(
                {
                    "name": path.name,
                    "path": str(path),
                    "present": content is not None,
                    **fields,
                }
            )
        payload = {
            "schema": "D320RuntimeCutoverPlanV2",
            "mode": "runtime_lifecycle",
            "source": {
                "commit": bound.source_commit,
                "tree_sha256": bound.source_tree_digest,
            },
            "target": {
                **target,
            },
            "owner_uid": os.geteuid(),
            "predecessor": dict(predecessor)
            if isinstance(predecessor, Mapping)
            else None,
            "compatibility": compatibility,
            "qualification": qualification,
            "files": snapshots,
            "extra_effects": _v2_plan_effects(home, bound.source_commit),
            "manager_states": {name: dict(value) for name, value in bound.states},
            "actions": ["install", "activate", "observe", "commit"],
            "inverse_actions": [
                "restore_manager",
                "restore_files",
                "discard_generation",
            ],
            "output_manifest_digest": "pending",
        }
        encoded = _d320_canonical_json(payload)
        _revalidate_cutover_inputs(bound)
        if isinstance(predecessor, Mapping) and predecessor.get("consumer_pin") is True:
            _revalidate_v2_predecessor(bound.release_root, predecessor)
        return {
            "status": (
                "runtime_lifecycle_plan_blocked"
                if reason_codes
                else "runtime_lifecycle_plan_ready"
            ),
            "plan": payload,
            "plan_sha256": hashlib.sha256(encoded).hexdigest(),
            "reason_codes": reason_codes,
            "raw_output": "not_returned",
        }
    except RuntimeLifecycleError as exc:
        return {"status": str(exc), "raw_output": "not_returned"}


def _bind_systemd_states(bound: _BoundCutover, systemctl: Systemctl) -> _BoundCutover:
    """Bind manager state before the installer changes either unit namespace."""

    states = tuple((unit, _show(systemctl, unit)) for unit in _V2_MANAGER_UNITS)
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


def _install_attested_runtime(
    home: Path,
    *,
    stage_name: str | None = None,
    record_setup: Callable[[Path], None] | None = None,
    reserve_setup: Callable[[Path, Path, str], None] | None = None,
    before_publish: Callable[[Path, object, dict[str, str]], None] | None = None,
) -> Mapping[str, object]:
    """Cross the existing attested-installer boundary; never compose a wrapper."""

    if record_setup is None or reserve_setup is None or before_publish is None:
        raise _error("runtime_lifecycle_v2_journal_unavailable")

    repository = Path(__file__).resolve().parents[2]

    def unavailable_before_publish(
        _stage: Path, _layout: object, _output_digests: dict[str, str]
    ) -> None:
        raise _error("runtime_lifecycle_v2_journal_unavailable")

    selected_stage = stage_name or f".the-hive-runtime.stage.{secrets.token_hex(16)}"
    setup = record_setup
    seal = before_publish or unavailable_before_publish

    try:
        _source_tree_binding(repository)
        with _bound_installer_entry(repository) as entry:
            installer = runpy.run_path(f"/proc/self/fd/{entry.descriptor}")
            install = installer.get("_install_attested_runtime")
            if not callable(install):
                raise _error("runtime_lifecycle_installer_invalid")
            result = install(
                home=home,
                stage_name=selected_stage,
                record_setup=setup,
                reserve_setup=reserve_setup,
                before_publish=seal,
            )
    except RuntimeLifecycleError:
        raise
    except Exception as exc:
        raise _error("runtime_lifecycle_install_failed") from exc
    if not isinstance(result, Mapping) or result.get("status") != "installed":
        raise _error("runtime_lifecycle_install_failed")
    return result


def _v2_bootstrap_store(home: Path) -> None:
    """Create only the private coordinator path, durably and restartably."""

    target = home.lstat()
    if (
        stat.S_ISLNK(target.st_mode)
        or not stat.S_ISDIR(target.st_mode)
        or target.st_uid != os.geteuid()
    ):
        raise _error("runtime_lifecycle_home_invalid")
    directories = (
        home / ".local",
        home / ".local" / "state",
        home / ".local" / "state" / "codex-master-mcp",
        _v2_journal_path(home).parent,
    )
    for directory in directories:
        _bound_path_from_home(home, directory)
        try:
            directory.mkdir(mode=0o700)
            created = True
        except FileExistsError:
            created = False
        except OSError as exc:
            raise _error("runtime_lifecycle_store_unavailable") from exc
        descriptor = -1
        try:
            descriptor = os.open(
                directory,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
            opened = os.fstat(descriptor)
            named = directory.lstat()
            if (
                not stat.S_ISDIR(opened.st_mode)
                or stat.S_ISLNK(named.st_mode)
                or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
                or opened.st_uid != os.geteuid()
                or (not created and stat.S_IMODE(opened.st_mode) != 0o700)
            ):
                raise _error("runtime_lifecycle_store_untrusted")
            if created:
                os.fchmod(descriptor, 0o700)
            os.fsync(descriptor)
        except RuntimeLifecycleError:
            raise
        except OSError as exc:
            raise _error("runtime_lifecycle_store_unavailable") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if created:
            parent_fd = -1
            try:
                parent_fd = os.open(
                    directory.parent,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                )
                os.fsync(parent_fd)
            except OSError as exc:
                raise _error("runtime_lifecycle_store_unavailable") from exc
            finally:
                if parent_fd >= 0:
                    os.close(parent_fd)

    lock = home / ".local" / "state" / "codex-master-mcp" / "hive" / _LOCK_NAME
    descriptor = -1
    created = False
    try:
        try:
            descriptor = os.open(
                lock,
                os.O_RDWR
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                0o600,
            )
            created = True
        except FileExistsError:
            descriptor = os.open(
                lock,
                os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            )
        info = os.fstat(descriptor)
        named = lock.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_ISLNK(named.st_mode)
            or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
            or (not created and stat.S_IMODE(info.st_mode) != 0o600)
        ):
            raise _error("runtime_lifecycle_lock_invalid")
        if created:
            os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    except RuntimeLifecycleError:
        raise
    except OSError as exc:
        raise _error("runtime_lifecycle_store_unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if created:
        parent_fd = -1
        try:
            parent_fd = os.open(
                lock.parent,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
            os.fsync(parent_fd)
        except OSError as exc:
            raise _error("runtime_lifecycle_store_unavailable") from exc
        finally:
            if parent_fd >= 0:
                os.close(parent_fd)


def _v2_require_existing_lifecycle_lock(home: Path) -> None:
    for path in (
        home / ".local",
        home / ".local" / "state",
        home / ".local" / "state" / "codex-master-mcp",
        _v2_journal_path(home).parent,
    ):
        _private_directory(path)
    lock = home / ".local" / "state" / "codex-master-mcp" / "hive" / _LOCK_NAME
    try:
        info = lock.lstat()
    except OSError as exc:
        raise _error("runtime_lifecycle_lock_unavailable") from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise _error("runtime_lifecycle_lock_invalid")


def _v2_install_phase(
    *, home: Path, plan_result: Mapping[str, object], systemctl: Systemctl
) -> dict[str, object]:
    plan_payload = plan_result.get("plan")
    plan_sha256 = plan_result.get("plan_sha256")
    if not isinstance(plan_payload, Mapping) or not isinstance(plan_sha256, str):
        raise _error("runtime_lifecycle_plan_invalid")
    _v2_bootstrap_store(home)
    _v2_require_existing_lifecycle_lock(home)
    with _lifecycle_lock(home) as lease:
        bound = _bind_systemd_states(_bind_cutover_inputs(home), systemctl)
        _revalidate_cutover_inputs(bound)
        fresh = plan(home=home, systemctl=systemctl)
        if (
            fresh.get("status") != "runtime_lifecycle_plan_ready"
            or fresh.get("plan_sha256") != plan_sha256
        ):
            raise _error("runtime_lifecycle_plan_changed")
        predecessor = plan_payload.get("predecessor")
        if not isinstance(predecessor, Mapping):
            raise _error("runtime_lifecycle_predecessor_missing")
        _revalidate_v2_predecessor(bound.release_root, predecessor)
        prior = _v2_load_journal(home)
        if prior is not None and prior.payload["phase"] not in {
            "COMMITTED",
            "ROLLED_BACK",
        }:
            raise _error("runtime_lifecycle_transaction_active")
        old_raw = _regular_bytes(
            _v2_journal_path(home), maximum=_D320_MAX_ENVELOPE_BYTES, mode=0o600
        )
        old_digest = (
            hashlib.sha256(old_raw).hexdigest() if old_raw is not None else None
        )
        stage_name = f".the-hive-runtime.stage.{secrets.token_hex(16)}"
        journal = _v2_initial_journal(
            bound,
            plan=plan_payload,
            plan_sha256=plan_sha256,
            stage_name=stage_name,
            previous=prior,
        )
        _v2_store_journal(home, journal, expected_digest=old_digest, lease=lease)

        def record_setup(stage: Path) -> None:
            nonlocal journal
            if stage != home / ".local" / "lib" / stage_name:
                raise _error("runtime_lifecycle_stage_setup_invalid")
            before = {item["path"]: item for item in journal.payload["extra_effects"]}
            after = _v2_capture_effects(home, bound.source_commit, stage_name)
            temp_to_target = {
                str(_v2_setup_temp_path(journal.payload, Path(path))): path
                for path in _v2_expected_effects(home, bound.source_commit, stage_name)
            }
            setup_records = {
                temp_to_target[step["effect"]]: step["sha256"]
                for step in journal.payload["steps"]
                if step["action"] == "effect_created"
            }
            created = []
            for effect in after:
                path = effect["path"]
                if path in {
                    str(_v2_journal_path(home)),
                    str(home / ".local/state/codex-master-mcp/hive" / _LOCK_NAME),
                }:
                    continue
                old = before[path]
                if _v2_effect_identity_digest(old) == _v2_effect_identity_digest(
                    effect
                ):
                    continue
                if old["present"] or not effect["present"]:
                    raise _error(
                        "runtime_lifecycle_installer_setup_changed_existing:"
                        + str(path)
                    )
                reserved = setup_records.get(path)
                if reserved != _v2_setup_reservation_digest(Path(path), Path(path)):
                    raise _error("runtime_lifecycle_installer_setup_unreserved")
                created.append(effect)
            if not created:
                raise _error("runtime_lifecycle_installer_setup_empty")
            if str(stage) not in setup_records:
                raise _error("runtime_lifecycle_installer_stage_unbound")

        def reserve_setup(path: Path, temporary: Path, digest: str) -> None:
            nonlocal journal
            effects = {item["path"]: item for item in journal.payload["extra_effects"]}
            effect = effects.get(str(path))
            if (
                not isinstance(effect, Mapping)
                or effect["present"]
                or temporary != _v2_setup_temp_path(journal.payload, path)
                or not isinstance(digest, str)
                or re.fullmatch(_SHA256_HEX_PATTERN, digest) is None
            ):
                raise _error("runtime_lifecycle_installer_setup_unbound")
            if any(
                step["action"] == "effect_created" and step["effect"] == str(temporary)
                for step in journal.payload["steps"]
            ):
                raise _error("runtime_lifecycle_installer_setup_duplicate")
            journal = _v2_transition(
                home,
                journal,
                lease=lease,
                phase="INTENT",
                action="effect_created",
                effect=str(temporary),
                digest=digest,
            )

        def seal_before_publish(
            stage: Path, layout: object, outputs: dict[str, str]
        ) -> None:
            nonlocal journal
            if (
                stage.name != stage_name
                or stage.parent != home / ".local" / "lib"
                or getattr(layout, "manifest_digest", None) is None
                or not isinstance(outputs, dict)
                or set(outputs)
                != {
                    "mcp_launcher",
                    "hourly_service",
                    "hourly_timer",
                    "pricing_launcher",
                    "pricing_service",
                    "pricing_timer",
                    "legacy_launcher",
                }
            ):
                raise _error("runtime_lifecycle_stage_seal_invalid")
            manifest_digest = getattr(layout, "manifest_digest")
            if not isinstance(manifest_digest, str) or not manifest_digest.startswith(
                "sha256:"
            ):
                raise _error("runtime_lifecycle_stage_seal_invalid")
            _d320_sha256(manifest_digest[7:])
            manifest_bound_plan = dict(journal.payload["plan"])
            manifest_bound_plan["output_manifest_digest"] = manifest_digest
            qualification_reason = _v2_qualification_record_reason(manifest_bound_plan)
            if qualification_reason is not None:
                raise _error(qualification_reason)
            compatibility = journal.payload["plan"].get("compatibility")
            if not isinstance(compatibility, Mapping):
                raise _error("runtime_lifecycle_stage_seal_invalid")
            profile_digest = compatibility.get("sha256")
            if not isinstance(profile_digest, str):
                raise _error("runtime_lifecycle_stage_seal_invalid")
            _verify_candidate_compatibility_profile_stage(layout, profile_digest)
            for digest in outputs.values():
                _d320_sha256(digest)
            stage_temporary = _v2_setup_temp_path(journal.payload, stage)
            stage_reservation = next(
                (
                    step["sha256"]
                    for step in journal.payload["steps"]
                    if step["action"] == "effect_created"
                    and step["effect"] == str(stage_temporary)
                ),
                None,
            )
            stage_identity = _v2_setup_reservation_digest(stage, stage)
            generation_path = (
                home / ".local/lib/the-hive-runtime/generations" / bound.source_commit
            )
            if (
                stage_reservation != stage_identity
                or not generation_path.parent.is_dir()
            ):
                raise _error("runtime_lifecycle_stage_seal_invalid")
            generation_identity = _v2_setup_reservation_digest(
                stage,
                generation_path,
                parent_path=generation_path.parent,
            )
            sealed = {
                "generation": bound.source_commit,
                "manifest_digest": manifest_digest,
                "output_sha256": dict(outputs),
                "stage_identity_sha256": stage_identity,
                "generation_identity_sha256": generation_identity,
            }
            _revalidate_cutover_inputs(bound)
            _revalidate_v2_predecessor(bound.release_root, predecessor)
            journal = _v2_transition(
                home,
                journal,
                lease=lease,
                phase="SEALED",
                action="stage_sealed",
                effect=str(stage),
                digest=manifest_digest[7:],
                updates={"sealed": sealed},
            )

        install_result = _install_attested_runtime(
            home,
            stage_name=stage_name,
            record_setup=record_setup,
            reserve_setup=reserve_setup,
            before_publish=seal_before_publish,
        )
        sealed = journal.payload["sealed"]
        if (
            journal.payload["phase"] != "SEALED"
            or not isinstance(sealed, Mapping)
            or install_result.get("generation") != bound.source_commit
            or install_result.get("manifest_digest") != sealed["manifest_digest"]
        ):
            raise _error("runtime_lifecycle_installer_result_invalid")
        before_files = {item["path"]: item for item in journal.payload["files"]}
        installed_readbacks: list[tuple[str, str, str]] = []
        for path, _content, mode in bound.files:
            snapshot = _v2_capture_managed_file(path, mode)
            prior_snapshot = before_files[str(path)]
            if snapshot != prior_snapshot:
                installed_readbacks.append(
                    (
                        "effect_installed",
                        str(path),
                        hashlib.sha256(_d320_canonical_json(snapshot)).hexdigest(),
                    )
                )
        journal = _v2_transition(
            home,
            journal,
            lease=lease,
            phase="INSTALLED",
            action="generation_published",
            effect=str(
                home
                / ".local"
                / "lib"
                / "the-hive-runtime"
                / "generations"
                / bound.source_commit
            ),
            digest=sealed["manifest_digest"][7:],
            additional_steps=installed_readbacks,
        )
    return {
        "status": "runtime_lifecycle_install_complete",
        "plan_sha256": plan_sha256,
        "journal_phase": journal.payload["phase"],
        "raw_output": "not_returned",
    }


def _v2_activate_phase(
    *, home: Path, plan_sha256: str, systemctl: Systemctl
) -> dict[str, object]:
    _v2_require_existing_lifecycle_lock(home)
    with _lifecycle_lock(home) as lease:
        journal = _v2_load_journal(home)
        if journal is None:
            raise _error("runtime_lifecycle_journal_missing")
        payload = journal.payload
        if payload["phase"] != "INSTALLED" or payload["plan_sha256"] != plan_sha256:
            raise _error("runtime_lifecycle_phase_changed")
        bound = _bind_systemd_states(_bind_cutover_inputs(home), systemctl)
        if (
            bound.source_commit != payload["source"]["commit"]
            or bound.source_tree_digest != payload["source"]["tree_sha256"]
            or dict(bound.states) != payload["manager_pre"]
        ):
            raise _error("runtime_lifecycle_input_changed")
        sealed = payload["sealed"]
        identity = _runtime_identity(bound.release_root)
        if (
            not isinstance(sealed, Mapping)
            or not isinstance(identity, Mapping)
            or identity.get("generation") != sealed["generation"]
            or identity.get("manifest_digest") != sealed["manifest_digest"]
        ):
            raise _error("runtime_lifecycle_installed_runtime_changed")
        _v2_verify_installed_outputs(home, sealed)
        root_receipt_digest, root_lock_fd = _verify_root_hook_effect_receipt(
            generation=str(sealed["generation"]),
            manifest_digest=str(sealed["manifest_digest"]),
            hold_lock=True,
        )
        try:
            journal = _v2_record_owner_evidence(
                home,
                journal,
                lease=lease,
                phase="ACTIVATED",
                effect=str(_ROOT_HOOK_ABI_PARENT / _ROOT_HOOK_EFFECT_RECEIPT),
                digest=root_receipt_digest,
            )
        finally:
            _release_root_hook_effect_lock(root_lock_fd)
        migrations = _legacy_requires_migration(bound)
        commands: list[tuple[tuple[str, ...], str, str]] = [
            (
                ("daemon-reload",),
                "manager:" + _NEW_SERVICE,
                "manager_reload_before_activation",
            )
        ]
        if migrations:
            commands.extend(
                (
                    (
                        ("stop", _LEGACY_SERVICE),
                        "manager:" + _LEGACY_SERVICE,
                        "legacy_service_stop",
                    ),
                    (
                        ("disable", "--now", _LEGACY_TIMER),
                        "manager:" + _LEGACY_TIMER,
                        "legacy_timer_disable",
                    ),
                )
            )
        commands.append(
            (
                ("enable", "--now", _NEW_TIMER),
                "manager:" + _NEW_TIMER,
                "new_timer_enable",
            )
        )
        if migrations:
            commands.append(
                (
                    ("daemon-reload",),
                    "manager:" + _PRICING_UNITS[0],
                    "manager_reload_after_legacy_removal",
                )
            )
        for arguments, effect, label in commands:
            _revalidate_cutover_inputs(bound)
            _v2_verify_installed_outputs(home, sealed)
            journal = _v2_transition(
                home,
                journal,
                lease=lease,
                phase="ACTIVATED",
                action="manager_mutation",
                effect=effect,
                digest=hashlib.sha256(
                    _d320_canonical_json(
                        {"operation": label, "arguments": list(arguments)}
                    )
                ).hexdigest(),
            )
            _cutover_systemctl_mutate(systemctl, arguments, phase=label)
        if migrations:
            for path, content, _mode in bound.files:
                if (
                    path.name in {_LEGACY_SERVICE, _LEGACY_TIMER}
                    and content is not None
                ):
                    journal = _v2_transition(
                        home,
                        journal,
                        lease=lease,
                        phase="ACTIVATED",
                        action="effect_installed",
                        effect=str(path),
                        digest=hashlib.sha256(content).hexdigest(),
                    )
            _remove_legacy_hourly_units(bound)
        current = _bind_systemd_states(_bind_cutover_inputs(home), systemctl)
        states = dict(current.states)
        if (
            states[_NEW_TIMER].get("UnitFileState") != "enabled"
            or states[_NEW_TIMER].get("ActiveState") != "active"
            or states[_LEGACY_TIMER].get("UnitFileState") != "disabled"
            or states[_LEGACY_TIMER].get("ActiveState") != "inactive"
            or states[_LEGACY_SERVICE].get("ActiveState") != "inactive"
        ):
            raise _error("runtime_lifecycle_manager_readback_failed")
    return {
        "status": "runtime_lifecycle_activation_complete",
        "plan_sha256": plan_sha256,
        "journal_phase": journal.payload["phase"],
        "raw_output": "not_returned",
    }


def _v2_observe_phase(
    *, home: Path, plan_sha256: str, systemctl: Systemctl
) -> dict[str, object]:
    _v2_require_existing_lifecycle_lock(home)
    with _lifecycle_lock(home) as lease:
        journal = _v2_load_journal(home)
        if journal is None or journal.payload["phase"] != "ACTIVATED":
            raise _error("runtime_lifecycle_phase_changed")
        payload = journal.payload
        if payload["plan_sha256"] != plan_sha256:
            raise _error("runtime_lifecycle_plan_changed")
        bound = _bind_systemd_states(_bind_cutover_inputs(home), systemctl)
        if (
            bound.source_commit != payload["source"]["commit"]
            or bound.source_tree_digest != payload["source"]["tree_sha256"]
        ):
            raise _error("runtime_lifecycle_source_changed")
        sealed = payload["sealed"]
        identity = _runtime_identity(bound.release_root)
        states = dict(bound.states)
        if (
            not isinstance(sealed, Mapping)
            or not isinstance(identity, Mapping)
            or identity.get("generation") != sealed["generation"]
            or identity.get("manifest_digest") != sealed["manifest_digest"]
            or states[_NEW_TIMER].get("UnitFileState") != "enabled"
            or states[_NEW_TIMER].get("ActiveState") != "active"
            or states[_LEGACY_TIMER].get("UnitFileState") != "disabled"
            or states[_LEGACY_TIMER].get("ActiveState") != "inactive"
            or states[_LEGACY_SERVICE].get("ActiveState") != "inactive"
        ):
            raise _error("runtime_lifecycle_manager_state_changed")
        _v2_verify_installed_outputs(home, sealed)
        _observe_argumentless_installed_probe(home)
        bound = _bind_systemd_states(_bind_cutover_inputs(home), systemctl)
        _v2_verify_installed_outputs(home, sealed)
        post = _v2_capture_post(
            home, payload["source"]["commit"], payload["stage_name"], bound
        )
        files = post["files"]
        effects = post["extra_effects"]
        managers = post["manager_states"]
        readbacks = [
            (
                "effect_readback",
                item["path"],
                hashlib.sha256(_d320_canonical_json(item)).hexdigest(),
            )
            for item in (*files, *effects)
        ] + [
            (
                "manager_readback",
                "manager:" + unit,
                hashlib.sha256(_d320_canonical_json(state)).hexdigest(),
            )
            for unit, state in managers.items()
        ]
        action, effect, digest = readbacks[0]
        journal = _v2_transition(
            home,
            journal,
            lease=lease,
            phase="OBSERVED",
            action=action,
            effect=effect,
            digest=digest,
            updates={"post": post},
            additional_steps=readbacks[1:],
        )
    return {
        "status": "runtime_lifecycle_observation_complete",
        "plan_sha256": plan_sha256,
        "journal_phase": journal.payload["phase"],
        "raw_output": "not_returned",
    }


def _v2_commit_phase(
    *, home: Path, plan_sha256: str, systemctl: Systemctl
) -> dict[str, object]:
    _v2_require_existing_lifecycle_lock(home)
    with _lifecycle_lock(home) as lease:
        journal = _v2_load_journal(home)
        if journal is None or journal.payload["phase"] != "OBSERVED":
            raise _error("runtime_lifecycle_phase_changed")
        payload = journal.payload
        if payload["plan_sha256"] != plan_sha256:
            raise _error("runtime_lifecycle_plan_changed")
        bound = _bind_systemd_states(_bind_cutover_inputs(home), systemctl)
        if (
            bound.source_commit != payload["source"]["commit"]
            or bound.source_tree_digest != payload["source"]["tree_sha256"]
        ):
            raise _error("runtime_lifecycle_source_changed")
        observed = _v2_capture_post(
            home, payload["source"]["commit"], payload["stage_name"], bound
        )
        if not _v2_post_matches(observed, payload["post"]):
            raise _error("runtime_lifecycle_observation_changed")
        sealed = payload["sealed"]
        if not isinstance(sealed, Mapping):
            raise _error("runtime_lifecycle_journal_invalid")
        plugin_receipt_digest = _verify_plugin_release_effect_receipt(
            home=home,
            generation=str(sealed["generation"]),
            manifest_digest=str(sealed["manifest_digest"]),
        )
        root_receipt_digest, root_lock_fd = _verify_root_hook_effect_receipt(
            generation=str(sealed["generation"]),
            manifest_digest=str(sealed["manifest_digest"]),
            hold_lock=True,
        )
        try:
            journal = _v2_record_owner_evidence(
                home,
                journal,
                lease=lease,
                phase="OBSERVED",
                effect=str(_ROOT_HOOK_ABI_PARENT / _ROOT_HOOK_EFFECT_RECEIPT),
                digest=root_receipt_digest,
            )
            journal = _v2_record_owner_evidence(
                home,
                journal,
                lease=lease,
                phase="OBSERVED",
                effect=str(
                    home / ".local/state/codex-master-mcp/hive" / _PLUGIN_EFFECT_RECEIPT
                ),
                digest=plugin_receipt_digest,
            )
            journal_path = str(_v2_journal_path(home))
            journal = _v2_transition(
                home,
                journal,
                lease=lease,
                phase="COMMITTED",
                action="commit_verified",
                effect=journal_path,
                digest=hashlib.sha256(
                    _d320_canonical_json(payload["post"])
                ).hexdigest(),
            )
        finally:
            _release_root_hook_effect_lock(root_lock_fd)
    return {
        "status": "runtime_lifecycle_commit_complete",
        "plan_sha256": plan_sha256,
        "journal_phase": journal.payload["phase"],
        "raw_output": "not_returned",
    }


def _v2_recovery_manager_states_are_bound(
    payload: Mapping[str, object],
    current: Mapping[str, Mapping[str, str]],
    previous: Mapping[str, Mapping[str, str]],
) -> bool:
    steps = payload["steps"]
    intents = {
        step["effect"].removeprefix("manager:")
        for step in steps
        if step["action"] == "manager_mutation"
    }
    expected = {unit: dict(state) for unit, state in previous.items()}
    expected[_NEW_TIMER].update(UnitFileState="enabled", ActiveState="active")
    expected[_LEGACY_TIMER].update(UnitFileState="disabled", ActiveState="inactive")
    expected[_LEGACY_SERVICE]["ActiveState"] = "inactive"
    for unit, state in current.items():
        if state == previous[unit]:
            continue
        if unit not in intents or state != expected[unit]:
            return False
    return True


def _v2_recovery_files_are_bound(
    home: Path, payload: Mapping[str, object], phase: str
) -> bool:
    snapshots = {item["path"]: item for item in payload["files"]}
    post = payload["post"]
    post_files = (
        {item["path"]: item for item in post["files"]}
        if isinstance(post, Mapping)
        else {}
    )
    effects = [
        step for step in payload["steps"] if step["action"] == "effect_installed"
    ]
    inverse_reservations = {
        step["effect"]: step["sha256"]
        for step in payload["steps"]
        if step["action"] == "inverse_reserved"
    }
    installed_snapshots = {
        step["effect"]: step["sha256"]
        for step in payload["steps"]
        if step["action"] == "effect_installed" and step["phase"] == "INSTALLED"
    }
    legacy_removals = {
        step["effect"]: step["sha256"]
        for step in effects
        if Path(step["effect"]).name in {_LEGACY_SERVICE, _LEGACY_TIMER}
    }
    try:
        for path_string, old in snapshots.items():
            path = Path(path_string)
            mode = (
                old["mode"]
                if old["present"]
                else (
                    0o600
                    if path.name == _OBSERVATION_NAME
                    else (
                        0o755
                        if path.name
                        in {
                            "the-hive-mcp",
                            _PRICING_LAUNCHER,
                            "codex_master_hive_hourly_probe.py",
                        }
                        else 0o644
                    )
                )
            )
            current = _regular_bytes(
                path,
                maximum=(
                    _MAX_HEALTH_BYTES
                    if path.name == ".the-hive-release-pointers.json"
                    else (
                        _MAX_OBSERVATION_BYTES
                        if path.name == _OBSERVATION_NAME
                        else _MAX_UNIT_BYTES
                    )
                ),
                mode=mode,
            )
            old_bytes = (
                base64.b64decode(old["bytes_b64"], validate=True)
                if old["present"]
                else None
            )
            if current == old_bytes:
                if not _v2_file_snapshot_identity_matches(path, old):
                    expected_inverse = inverse_reservations.get(path_string)
                    if (
                        expected_inverse is None
                        or _v2_file_identity_digest(path) != expected_inverse
                    ):
                        return False
                continue
            recorded_post = post_files.get(path_string)
            if phase in {"OBSERVED", "RECOVERING"} and recorded_post is not None:
                post_bytes = (
                    base64.b64decode(recorded_post["bytes_b64"], validate=True)
                    if recorded_post["present"]
                    else None
                )
                if current == post_bytes:
                    if not _v2_file_snapshot_identity_matches(path, recorded_post):
                        return False
                    continue
            installed_digest = installed_snapshots.get(path_string)
            if installed_digest is not None:
                installed_snapshot = _v2_capture_managed_file(path, mode)
                if (
                    hashlib.sha256(_d320_canonical_json(installed_snapshot)).hexdigest()
                    == installed_digest
                ):
                    continue
            reserved_digest = inverse_reservations.get(path_string)
            temporary = _v2_restore_temp_path(payload, path)
            try:
                temporary.lstat()
            except FileNotFoundError:
                pass
            except OSError:
                return False
            else:
                if (
                    reserved_digest is None
                    or _v2_file_identity_digest(temporary) != reserved_digest
                    or _regular_bytes(temporary, maximum=_MAX_HEALTH_BYTES, mode=mode)
                    != old_bytes
                ):
                    return False
                continue
            if path.name in {_LEGACY_SERVICE, _LEGACY_TIMER} and current is None:
                if legacy_removals.get(path_string) == old["sha256"]:
                    continue
            return False
    except (OSError, RuntimeLifecycleError, ValueError, TypeError):
        return False
    return True


def _v2_file_snapshot_identity_matches(
    path: Path, snapshot: Mapping[str, object]
) -> bool:
    if not snapshot["present"]:
        try:
            path.lstat()
        except FileNotFoundError:
            return True
        except OSError:
            return False
        return False
    try:
        info = path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISREG(info.st_mode)
        and info.st_dev == snapshot["dev"]
        and info.st_ino == snapshot["ino"]
        and info.st_uid == snapshot["uid"]
        and info.st_gid == snapshot["gid"]
        and stat.S_IMODE(info.st_mode) == snapshot["mode"]
        and info.st_nlink == snapshot["nlink"]
        and info.st_size == snapshot["size"]
    )


def _v2_file_identity_digest(path: Path) -> str:
    try:
        item = path.lstat()
    except OSError as exc:
        raise _error("runtime_lifecycle_recovery_hold") from exc
    if (
        stat.S_ISLNK(item.st_mode)
        or not stat.S_ISREG(item.st_mode)
        or item.st_uid != os.geteuid()
        or item.st_nlink != 1
    ):
        raise _error("runtime_lifecycle_recovery_hold")
    identity = {
        "type": "file",
        "dev": item.st_dev,
        "ino": item.st_ino,
        "uid": item.st_uid,
        "gid": item.st_gid,
        "mode": stat.S_IMODE(item.st_mode),
        "nlink": item.st_nlink,
        "size": item.st_size,
    }
    return hashlib.sha256(_d320_canonical_json(identity)).hexdigest()


def _v2_setup_reservation_digest(
    path: Path, target: Path, *, parent_path: Path | None = None
) -> str:
    try:
        item = path.lstat()
        parent = (parent_path or path.parent).lstat()
    except OSError as exc:
        raise _error("runtime_lifecycle_recovery_hold") from exc
    if (
        stat.S_ISLNK(item.st_mode)
        or item.st_uid != os.geteuid()
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.geteuid()
    ):
        raise _error("runtime_lifecycle_recovery_hold")
    if stat.S_ISDIR(item.st_mode):
        selected = {
            "type": "directory",
            "dev": item.st_dev,
            "ino": item.st_ino,
            "uid": item.st_uid,
            "gid": item.st_gid,
            "mode": stat.S_IMODE(item.st_mode),
        }
    elif stat.S_ISREG(item.st_mode) and item.st_nlink == 1:
        selected = {
            "type": "file",
            "dev": item.st_dev,
            "ino": item.st_ino,
            "uid": item.st_uid,
            "gid": item.st_gid,
            "mode": stat.S_IMODE(item.st_mode),
            "nlink": item.st_nlink,
        }
    else:
        raise _error("runtime_lifecycle_recovery_hold")
    selected["parent_dev"] = parent.st_dev
    selected["parent_ino"] = parent.st_ino
    selected["target"] = str(target)
    selected["target"] = str(target)
    return hashlib.sha256(_d320_canonical_json(selected)).hexdigest()


def _v2_restore_temp_path(payload: Mapping[str, object], target: Path) -> Path:
    suffix = hashlib.sha256(str(target).encode("utf-8")).hexdigest()[:16]
    return target.parent / f".{target.name}.v2-restore-{payload['journal_id']}-{suffix}"


def _v2_remove_owned_stage(
    home: Path,
    payload: Mapping[str, object],
    *,
    require_seal: bool,
    remove: bool = True,
) -> None:
    stage = home / ".local" / "lib" / str(payload["stage_name"])
    try:
        before = stage.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise _error("runtime_lifecycle_recovery_hold") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISDIR(before.st_mode)
        or before.st_uid != os.geteuid()
        or stat.S_IMODE(before.st_mode) != 0o700
    ):
        raise _error("runtime_lifecycle_recovery_hold")
    sealed = payload["sealed"]
    if isinstance(sealed, Mapping):
        expected_identity = sealed["stage_identity_sha256"]
    else:
        temporary = _v2_setup_temp_path(payload, stage)
        expected_identity = next(
            (
                step["sha256"]
                for step in payload["steps"]
                if step["action"] == "effect_created"
                and step["effect"] == str(temporary)
            ),
            None,
        )
    if (
        not isinstance(expected_identity, str)
        or _v2_setup_reservation_digest(stage, stage) != expected_identity
    ):
        raise _error("runtime_lifecycle_recovery_hold")
    if require_seal:
        try:
            from the_hive.runtime_layout import RuntimeLayout

            stage_layout = RuntimeLayout.from_runtime_root(stage)
            install_script = (
                Path(__file__).resolve().parents[2]
                / "scripts"
                / "the-hive-hive-hourly-probe-install"
            )
            installer = runpy.run_path(os.fspath(install_script))
            installer["_validate_runtime_image_stage"](stage=stage, home=home)
            hourly_service, hourly_timer = installer["_staged_hourly_probe_unit_bytes"](
                layout=stage_layout, generation=payload["source"]["commit"]
            )
            pricing_service, pricing_timer = installer[
                "_staged_pricing_inventory_unit_bytes"
            ](layout=stage_layout)
            outputs = {
                "mcp_launcher": installer["_attested_stable_mcp_launcher_bytes"](
                    stage_layout
                ),
                "hourly_service": hourly_service,
                "hourly_timer": hourly_timer,
                "pricing_launcher": installer[
                    "_attested_pricing_inventory_launcher_bytes"
                ](stage_layout),
                "pricing_service": pricing_service,
                "pricing_timer": pricing_timer,
                "legacy_launcher": installer["_attested_legacy_probe_launcher_bytes"](
                    stage_layout
                ),
            }
        except Exception as exc:
            raise _error("runtime_lifecycle_recovery_hold") from exc
        sealed = payload["sealed"]
        if (
            not isinstance(sealed, Mapping)
            or stage_layout.root != stage
            or stage_layout.manifest_digest != sealed["manifest_digest"]
            or {
                name: hashlib.sha256(content).hexdigest()
                for name, content in outputs.items()
            }
            != sealed["output_sha256"]
        ):
            raise _error("runtime_lifecycle_recovery_hold")
    if not remove:
        return
    try:
        if _v2_setup_reservation_digest(stage, stage) != expected_identity:
            raise _error("runtime_lifecycle_recovery_hold")
        _v2_remove_journaled_effect(
            home,
            payload,
            path=stage,
            kind="stage",
            digest=expected_identity,
        )
    except (OSError, RuntimeLifecycleError) as exc:
        raise _error("runtime_lifecycle_recovery_hold") from exc


def _v2_setup_temp_path(payload: Mapping[str, object], target: Path) -> Path:
    if (
        target.name == ".hook-session-pins-v1.lock"
        and target.parent.name == "hook-session-pins-v1"
    ):
        return _v2_setup_temp_path(payload, target.parent) / target.name
    transaction = str(payload["stage_name"]).rsplit(".", 1)[-1]
    selected = hashlib.sha256(os.fsencode(target)).hexdigest()[:16]
    return target.parent / f".{target.name}.hive-v2-setup-{transaction}-{selected}"


def _v2_remove_journaled_effect(
    home: Path,
    payload: Mapping[str, object],
    *,
    path: Path,
    kind: str,
    digest: str,
) -> None:
    """Remove one setup artifact only after a NOREPLACE identity handoff."""

    _bound_path_from_home(home, path)
    parent_fd = -1
    name = path.name
    quarantine = (
        ".hive-lifecycle-recovery-"
        + hashlib.sha256(
            (str(payload["journal_id"]) + "\0" + str(path)).encode("utf-8")
        ).hexdigest()[:32]
    )

    def current_identity(selected: str) -> Mapping[str, object] | None:
        try:
            info = os.stat(selected, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise _error("runtime_lifecycle_recovery_hold") from exc
        if stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid():
            raise _error("runtime_lifecycle_recovery_hold")
        if stat.S_ISDIR(info.st_mode):
            effect_type = "directory"
        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
            effect_type = "file"
        else:
            raise _error("runtime_lifecycle_recovery_hold")
        return {
            "type": effect_type,
            "dev": info.st_dev,
            "ino": info.st_ino,
            "uid": info.st_uid,
            "gid": info.st_gid,
            "mode": stat.S_IMODE(info.st_mode),
            "nlink": info.st_nlink,
        }

    def matches(identity: Mapping[str, object] | None) -> bool:
        directory_kinds = {
            "state_parent",
            "install_state",
            "local_bin",
            "local_libexec",
            "hook_pin_parent",
            "hook_pin_authority",
            "config",
            "config_systemd",
            "units",
            "library",
            "release_root",
            "generations",
            "stage",
            "generation",
        }
        if identity is None or identity["type"] != (
            "directory" if kind in directory_kinds else "file"
        ):
            return False
        stable = {
            key: identity[key] for key in ("type", "dev", "ino", "uid", "gid", "mode")
        }
        if identity["type"] == "file":
            stable["nlink"] = identity["nlink"]
        if kind != "managed_file":
            parent = os.fstat(parent_fd)
            stable["parent_dev"] = parent.st_dev
            stable["parent_ino"] = parent.st_ino
            stable["target"] = str(path)
        return hashlib.sha256(_d320_canonical_json(stable)).hexdigest() == digest

    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise _error("runtime_lifecycle_recovery_hold")
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    try:
        selected_parent = path.parent
        selected_name = name
        try:
            path.parent.lstat()
        except FileNotFoundError:
            temporary_path = _v2_setup_temp_path(payload, path)
            selected_parent = temporary_path.parent
            selected_name = temporary_path.name
        parent_fd = os.open(
            selected_parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        source_name = selected_name
        source_identity = current_identity(source_name)
        if source_identity is None:
            temporary_name = _v2_setup_temp_path(payload, path).name
            temporary_identity = current_identity(temporary_name)
            if temporary_identity is not None:
                source_name = temporary_name
                source_identity = temporary_identity
        quarantine_identity = current_identity(quarantine)
        if source_identity is None:
            if quarantine_identity is None:
                return
            if not matches(quarantine_identity):
                raise _error("runtime_lifecycle_recovery_hold")
        else:
            if quarantine_identity is not None or not matches(source_identity):
                raise _error("runtime_lifecycle_recovery_hold")
            result = renameat2(
                parent_fd,
                os.fsencode(source_name),
                parent_fd,
                os.fsencode(quarantine),
                1,
            )
            if result != 0:
                error_number = ctypes.get_errno()
                raise OSError(error_number, os.strerror(error_number))
            quarantine_identity = current_identity(quarantine)
            if not matches(quarantine_identity):
                if current_identity(name) is None:
                    renameat2(
                        parent_fd,
                        os.fsencode(quarantine),
                        parent_fd,
                        os.fsencode(name),
                        1,
                    )
                raise _error("runtime_lifecycle_recovery_hold")
        os.fsync(parent_fd)
        if kind in {"stage", "generation"}:
            shutil.rmtree(path.parent / quarantine)
        elif quarantine_identity["type"] == "directory":
            os.rmdir(quarantine, dir_fd=parent_fd)
        else:
            os.unlink(quarantine, dir_fd=parent_fd)
        os.fsync(parent_fd)
    except (OSError, RuntimeLifecycleError) as exc:
        if isinstance(exc, RuntimeLifecycleError):
            raise
        raise _error("runtime_lifecycle_recovery_hold") from exc
    finally:
        if parent_fd >= 0:
            os.close(parent_fd)


def _v2_recover_phase(
    *, home: Path, plan_sha256: str, systemctl: Systemctl
) -> dict[str, object]:
    _v2_require_existing_lifecycle_lock(home)
    with _lifecycle_lock(home) as lease:
        journal = _v2_load_journal(home)
        if journal is None:
            raise _error("runtime_lifecycle_journal_missing")
        payload = journal.payload
        phase = str(payload["phase"])
        if payload["plan_sha256"] != plan_sha256:
            raise _error("runtime_lifecycle_plan_changed")
        if phase in {"COMMITTED", "ROLLED_BACK"}:
            return {
                "status": "runtime_lifecycle_recovery_not_needed",
                "journal_phase": phase,
                "raw_output": "not_returned",
            }
        if phase == "BLOCKED":
            raise _error("runtime_lifecycle_recovery_hold")
        bound = _bind_systemd_states(_bind_cutover_inputs(home), systemctl)
        target = payload["target"]
        info = home.lstat()
        if (
            str(home.resolve(strict=True)) != target["realpath"]
            or (info.st_dev, info.st_ino, info.st_uid, info.st_gid)
            != (target["dev"], target["ino"], target["uid"], target["gid"])
            or stat.S_IMODE(info.st_mode) != target["mode"]
            or bound.source_commit != payload["source"]["commit"]
            or bound.source_tree_digest != payload["source"]["tree_sha256"]
        ):
            raise _error("runtime_lifecycle_recovery_hold")

        snapshots = {item["path"]: item for item in payload["files"]}
        modes = {str(path): mode for path, _content, mode in bound.files}
        original_files: list[tuple[Path, bytes | None, int]] = []
        for path in (home / relative for relative in _V2_FILE_PATHS):
            item = snapshots[str(path)]
            mode = modes[str(path)]
            content = (
                base64.b64decode(item["bytes_b64"], validate=True)
                if item["present"]
                else None
            )
            original_files.append((path, content, mode))
        original_states = tuple(
            (unit, dict(state)) for unit, state in payload["manager_pre"].items()
        )
        initial_effects = {item["kind"]: item for item in payload["extra_effects"]}
        generation_effect = initial_effects["generations"]
        generations_before = frozenset(
            generation_effect["identity"]["children"]
            if generation_effect["present"]
            else ()
        )
        legacy_present = any(
            item["present"]
            for item in payload["files"]
            if item["name"] in {_LEGACY_SERVICE, _LEGACY_TIMER}
        )
        original = replace(
            bound,
            files=tuple(original_files),
            generations_before=generations_before,
            legacy_present=legacy_present,
            states=original_states,
        )

        current_states = dict(bound.states)
        pre_states = payload["manager_pre"]
        if not _v2_recovery_manager_states_are_bound(
            payload, current_states, pre_states
        ):
            raise _error("runtime_lifecycle_recovery_hold")
        if not _v2_recovery_files_are_bound(home, payload, phase):
            raise _error("runtime_lifecycle_recovery_hold")
        stage_path = home / ".local" / "lib" / payload["stage_name"]
        generation_path = (
            home
            / ".local/lib/the-hive-runtime/generations"
            / payload["source"]["commit"]
        )
        sealed = payload["sealed"]
        if phase != "INTENT":
            if not isinstance(sealed, Mapping):
                raise _error("runtime_lifecycle_recovery_hold")
            try:
                generation_path.lstat()
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise _error("runtime_lifecycle_recovery_hold") from exc
            else:
                if (
                    _v2_setup_reservation_digest(generation_path, generation_path)
                    != sealed["generation_identity_sha256"]
                ):
                    raise _error("runtime_lifecycle_recovery_hold")
        temp_to_target = {
            str(_v2_setup_temp_path(payload, Path(path))): path
            for path in _v2_expected_effects(
                home, payload["source"]["commit"], payload["stage_name"]
            )
        }
        setup_records = {
            temp_to_target[step["effect"]]: step["sha256"]
            for step in payload["steps"]
            if step["action"] == "effect_created"
        }
        for effect_path in _v2_expected_effects(
            home, payload["source"]["commit"], payload["stage_name"]
        ):
            temporary = _v2_setup_temp_path(payload, Path(effect_path))
            try:
                temporary.lstat()
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise _error("runtime_lifecycle_recovery_hold") from exc
            if (
                effect_path not in setup_records
                or _v2_setup_reservation_digest(temporary, Path(effect_path))
                != setup_records[effect_path]
            ):
                raise _error("runtime_lifecycle_recovery_hold")
        if phase in {"INTENT", "RECOVERING"}:
            current_effects = _v2_capture_effects(
                home, payload["source"]["commit"], payload["stage_name"]
            )
            baseline = {item["path"]: item for item in payload["extra_effects"]}
            allowed_coordination = {
                str(_v2_journal_path(home)),
                str(
                    home / ".local/state/codex-master-mcp/hive/.runtime-lifecycle.lock"
                ),
            }
            for item in current_effects:
                if item["path"] in allowed_coordination:
                    continue
                if item["path"] == str(generation_path) and not item["present"]:
                    continue
                prior = baseline[item["path"]]
                if _v2_effect_identity_digest(item) == _v2_effect_identity_digest(
                    prior
                ):
                    if item["kind"] == "generation" and item["present"]:
                        raise _error("runtime_lifecycle_recovery_hold")
                    if (
                        item["path"] == str(stage_path)
                        and item["present"]
                        and item["path"] not in setup_records
                    ):
                        raise _error("runtime_lifecycle_recovery_hold")
                    continue
                if not item["present"] and prior["present"]:
                    raise _error("runtime_lifecycle_recovery_hold")
                if not item["present"] or setup_records.get(item["path"]) != (
                    _v2_setup_reservation_digest(Path(item["path"]), Path(item["path"]))
                ):
                    raise _error("runtime_lifecycle_recovery_hold")
        elif phase == "SEALED":
            stage_info = None
            try:
                stage_info = stage_path.lstat()
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise _error("runtime_lifecycle_recovery_hold") from exc
            if stage_info is not None:
                _v2_remove_owned_stage(home, payload, require_seal=True, remove=False)
            try:
                generation_info = generation_path.lstat()
            except FileNotFoundError:
                generation_info = None
            except OSError as exc:
                raise _error("runtime_lifecycle_recovery_hold") from exc
            if generation_info is not None:
                if (
                    _v2_setup_reservation_digest(generation_path, generation_path)
                    != sealed["generation_identity_sha256"]
                ):
                    raise _error("runtime_lifecycle_recovery_hold")
                try:
                    from the_hive.runtime_layout import RuntimeLayout

                    candidate = RuntimeLayout.from_runtime_root(generation_path)
                except Exception as exc:
                    raise _error("runtime_lifecycle_recovery_hold") from exc
                if candidate.manifest_digest != payload["sealed"]["manifest_digest"]:
                    raise _error("runtime_lifecycle_recovery_hold")
        elif phase in {"INSTALLED", "ACTIVATED", "OBSERVED"}:
            sealed = payload["sealed"]
            if not isinstance(sealed, Mapping):
                raise _error("runtime_lifecycle_recovery_hold")
            identity = _runtime_identity(bound.release_root)
            if (
                not isinstance(identity, Mapping)
                or identity.get("generation") != sealed["generation"]
                or identity.get("manifest_digest") != sealed["manifest_digest"]
            ):
                raise _error("runtime_lifecycle_recovery_hold")
            if phase == "INSTALLED" and current_states != pre_states:
                raise _error("runtime_lifecycle_recovery_hold")
        elif phase == "RECOVERING":
            # Resume is allowed only while each managed byte and manager state
            # remains either at its recorded pre-state or at a transaction
            # state already covered by the durable intent/readback log.
            pass
        else:
            raise _error("runtime_lifecycle_recovery_hold")

        if phase != "RECOVERING":
            journal = _v2_transition(
                home,
                journal,
                lease=lease,
                phase="RECOVERING",
                action="recovery_started",
                effect=str(_v2_journal_path(home)),
                digest=hashlib.sha256(journal.to_bytes()).hexdigest(),
                updates={"recovery_count": int(payload["recovery_count"]) + 1},
            )
        _v2_remove_owned_stage(
            home,
            payload,
            require_seal=bool(payload["sealed"]),
        )

        def restore_v2_file(path: Path, content: bytes, mode: int) -> None:
            nonlocal journal
            temp_path = _v2_restore_temp_path(payload, path)

            def reserve(target: Path, digest: str, created: bool) -> None:
                nonlocal journal
                current_steps = journal.payload["steps"]
                existing = next(
                    (
                        step
                        for step in current_steps
                        if step["phase"] == "RECOVERING"
                        and step["action"] == "inverse_reserved"
                        and step["effect"] == str(target)
                    ),
                    None,
                )
                if existing is not None:
                    if existing["sha256"] != digest:
                        raise _error("runtime_lifecycle_recovery_hold")
                    return
                if not created:
                    raise _error("runtime_lifecycle_recovery_hold")
                journal = _v2_transition(
                    home,
                    journal,
                    lease=lease,
                    phase="RECOVERING",
                    action="inverse_reserved",
                    effect=str(target),
                    digest=digest,
                )

            def applied(target: Path, digest: str) -> None:
                nonlocal journal
                existing = next(
                    (
                        step
                        for step in journal.payload["steps"]
                        if step["phase"] == "RECOVERING"
                        and step["action"] == "inverse_applied"
                        and step["effect"] == str(target)
                    ),
                    None,
                )
                if existing is not None:
                    if existing["sha256"] != digest:
                        raise _error("runtime_lifecycle_recovery_hold")
                    return
                journal = _v2_transition(
                    home,
                    journal,
                    lease=lease,
                    phase="RECOVERING",
                    action="inverse_applied",
                    effect=str(target),
                    digest=digest,
                )

            _atomic_restore(
                path,
                content,
                mode,
                temporary_path=temp_path,
                before_replace=reserve,
                after_replace=applied,
            )

        def remove_v2_file(path: Path) -> None:
            nonlocal journal
            info = path.lstat()
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_nlink != 1
            ):
                raise _error("runtime_lifecycle_recovery_hold")
            identity = {
                "identity": {
                    "type": "file",
                    "dev": info.st_dev,
                    "ino": info.st_ino,
                    "uid": info.st_uid,
                    "gid": info.st_gid,
                    "mode": stat.S_IMODE(info.st_mode),
                    "nlink": info.st_nlink,
                }
            }
            digest = _v2_effect_identity_digest(identity)
            existing = next(
                (
                    step
                    for step in journal.payload["steps"]
                    if step["phase"] == "RECOVERING"
                    and step["action"] == "inverse_reserved"
                    and step["effect"] == str(path)
                ),
                None,
            )
            if existing is None:
                journal = _v2_transition(
                    home,
                    journal,
                    lease=lease,
                    phase="RECOVERING",
                    action="inverse_reserved",
                    effect=str(path),
                    digest=digest,
                )
            elif existing["sha256"] != digest:
                raise _error("runtime_lifecycle_recovery_hold")
            _v2_remove_journaled_effect(
                home,
                journal.payload,
                path=path,
                kind="managed_file",
                digest=digest,
            )
            applied = next(
                (
                    step
                    for step in journal.payload["steps"]
                    if step["phase"] == "RECOVERING"
                    and step["action"] == "inverse_applied"
                    and step["effect"] == str(path)
                ),
                None,
            )
            if applied is None:
                journal = _v2_transition(
                    home,
                    journal,
                    lease=lease,
                    phase="RECOVERING",
                    action="inverse_applied",
                    effect=str(path),
                    digest=digest,
                )

        rollback = _restore_bound_state_result(
            original,
            systemctl,
            restore_file=restore_v2_file,
            remove_file=remove_v2_file,
            discard_generation=lambda selected: _discard_new_generation(
                selected,
                home=home,
                payload=journal.payload,
                expected_identity=(
                    journal.payload["sealed"]["generation_identity_sha256"]
                    if isinstance(journal.payload["sealed"], Mapping)
                    else None
                ),
            ),
        )
        if not rollback.restored:
            journal = _v2_transition(
                home,
                journal,
                lease=lease,
                phase="BLOCKED",
                action="blocked",
                effect=str(_v2_journal_path(home)),
                digest=hashlib.sha256(
                    _d320_canonical_json(
                        {"phase": rollback.phase, "error": rollback.error_code}
                    )
                ).hexdigest(),
            )
            return {
                "status": "runtime_lifecycle_recovery_blocked",
                "journal_phase": journal.payload["phase"],
                "raw_output": "not_returned",
            }
        created = sorted(
            setup_records.items(),
            key=lambda item: (item[0].count(os.sep), item[0]),
            reverse=True,
        )
        kinds = {item["path"]: item["kind"] for item in payload["extra_effects"]}
        for effect_path, digest in created:
            _v2_remove_journaled_effect(
                home,
                journal.payload,
                path=Path(effect_path),
                kind=kinds[effect_path],
                digest=digest,
            )
        for path, content, mode in original.files:
            if _regular_bytes(path, maximum=_MAX_UNIT_BYTES, mode=mode) != content:
                raise _error("runtime_lifecycle_recovery_hold")
        reservations = [
            step
            for step in journal.payload["steps"]
            if step["phase"] == "RECOVERING" and step["action"] == "inverse_reserved"
        ]
        applied_effects = {
            step["effect"]
            for step in journal.payload["steps"]
            if step["phase"] == "RECOVERING" and step["action"] == "inverse_applied"
        }
        for reservation in reservations:
            target = Path(reservation["effect"])
            if reservation["effect"] in applied_effects:
                continue
            if _v2_file_identity_digest(target) != reservation["sha256"]:
                continue
            journal = _v2_transition(
                home,
                journal,
                lease=lease,
                phase="RECOVERING",
                action="inverse_applied",
                effect=reservation["effect"],
                digest=reservation["sha256"],
            )
        journal = _v2_transition(
            home,
            journal,
            lease=lease,
            phase="ROLLED_BACK",
            action="rollback_verified",
            effect=str(_v2_journal_path(home)),
            digest=hashlib.sha256(
                _d320_canonical_json(
                    {"source_commit": original.source_commit, "restored": True}
                )
            ).hexdigest(),
        )
    return {
        "status": "runtime_lifecycle_recovery_complete",
        "journal_phase": journal.payload["phase"],
        "raw_output": "not_returned",
    }


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
            _HOURLY_PROBE_PROTECTED_HOME_BUS_BINDING,
            _HOURLY_PROBE_PROTECTED_HOME_MANAGER_BINDING,
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


def _atomic_restore(
    path: Path,
    content: bytes,
    mode: int,
    *,
    temporary_path: Path | None = None,
    before_replace: Callable[[Path, str, bool], None] | None = None,
    after_replace: Callable[[Path, str], None] | None = None,
) -> None:
    descriptor = -1
    temporary = Path()
    retain_temporary = False
    digest: str | None = None
    try:
        if temporary_path is None:
            descriptor, name = tempfile.mkstemp(
                prefix=f".{path.name}.rollback.", dir=path.parent
            )
            temporary = Path(name)
        else:
            temporary = temporary_path
            try:
                descriptor = os.open(
                    temporary,
                    os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                    mode,
                )
            except FileExistsError:
                descriptor = os.open(
                    temporary,
                    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                )
                item = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(item.st_mode)
                    or item.st_uid != os.geteuid()
                    or item.st_nlink != 1
                    or stat.S_IMODE(item.st_mode) != mode
                ):
                    raise _error("runtime_lifecycle_recovery_hold")
                chunks: list[bytes] = []
                while True:
                    chunk = os.read(descriptor, 65536)
                    if not chunk:
                        break
                    chunks.append(chunk)
                if b"".join(chunks) != content:
                    raise _error("runtime_lifecycle_recovery_hold")
                digest = _v2_file_identity_digest(temporary)
                os.close(descriptor)
                descriptor = -1
                if before_replace is not None:
                    retain_temporary = True
                    before_replace(path, digest, False)
        if digest is None:
            os.fchmod(descriptor, mode)
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            digest = _v2_file_identity_digest(temporary)
            if before_replace is not None:
                retain_temporary = True
                before_replace(path, digest, True)
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
        if after_replace is not None and digest is not None:
            after_replace(path, digest)
    except OSError as exc:
        raise _error("runtime_lifecycle_rollback_failed") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary != Path() and not retain_temporary:
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


def _discard_new_generation(
    bound: _BoundCutover,
    *,
    home: Path | None = None,
    payload: Mapping[str, object] | None = None,
    expected_identity: str | None = None,
) -> None:
    """Discard only this transaction's newly attested, unreferenced generation."""

    if bound.source_commit in bound.generations_before:
        return
    candidate = bound.release_root / "generations" / bound.source_commit
    try:
        candidate.lstat()
    except FileNotFoundError:
        if expected_identity is not None and candidate.parent.exists():
            if not isinstance(home, Path) or not isinstance(payload, Mapping):
                raise _error("runtime_lifecycle_recovery_hold")
            _v2_remove_journaled_effect(
                home,
                payload,
                path=candidate,
                kind="generation",
                digest=expected_identity,
            )
        return
    except OSError as exc:
        raise _error("runtime_lifecycle_rollback_failed") from exc
    try:
        from the_hive.runtime_layout import RuntimeLayout

        if expected_identity is not None and (
            not isinstance(home, Path)
            or not isinstance(payload, Mapping)
            or _v2_setup_reservation_digest(candidate, candidate) != expected_identity
        ):
            raise _error("runtime_lifecycle_recovery_hold")
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
        if expected_identity is not None:
            _v2_remove_journaled_effect(
                home,
                payload,
                path=candidate,
                kind="generation",
                digest=expected_identity,
            )
        else:
            shutil.rmtree(candidate)
    except RuntimeLifecycleError:
        raise
    except (OSError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        try:
            candidate.lstat()
        except FileNotFoundError:
            return
        except OSError:
            pass
        raise _error("runtime_lifecycle_rollback_failed") from exc


def _restore_bound_state_result(
    bound: _BoundCutover,
    systemctl: Systemctl,
    *,
    restore_file: Callable[[Path, bytes, int], None] | None = None,
    remove_file: Callable[[Path], None] | None = None,
    discard_generation: Callable[[_BoundCutover], None] | None = None,
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
                    if remove_file is None:
                        path.unlink()
                    else:
                        remove_file(path)
            elif current != content:
                if restore_file is None:
                    _atomic_restore(path, content, mode)
                else:
                    restore_file(path, content, mode)
            if _regular_bytes(path, maximum=maximum, mode=mode) != content:
                raise _error("runtime_lifecycle_rollback_failed")
    except (RuntimeLifecycleError, OSError):
        return _RollbackResult(
            False, _ROLLBACK_PHASE_FILE_RESTORE, "file_restore_failed"
        )

    try:
        if discard_generation is None:
            _discard_new_generation(bound)
        else:
            discard_generation(bound)
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
            if (
                state is not None
                and unit.endswith(".service")
                and state.get("LoadState") != "not-found"
                and not _state_is_active(state)
                and _show(systemctl, unit).get("ActiveState") == "failed"
            ):
                _systemctl_mutate(systemctl, ("reset-failed", unit))
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

    if failure.phase not in _CUTOVER_MUTATION_PHASES or not failure.status_whitelisted:
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
    return _CANARY_SYSTEMD_RUN_FAILURES.get(stderr, "runtime_canary_manager_failed")


def _systemd_run_default(arguments: tuple[str, ...]) -> Mapping[str, str]:
    """Create one transient user unit without inheriting the caller environment."""

    runtime_directory = os.fspath(_user_runtime_directory())
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

    runtime_directory = os.fspath(_user_runtime_directory())
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
            not isinstance(key, str) or not isinstance(value, str) or len(value) > 256
            for key, value in result.items()
        )
    ):
        raise _error("runtime_canary_manager_invalid")
    return dict(result)


def _canary_unit_owned(state: Mapping[str, str], binding: _CanaryUnitBinding) -> bool:
    return (
        state.get("LoadState") == "loaded"
        and state.get("Transient") == "yes"
        and state.get("Description") == binding.description
    )


def _start_canary_unit(systemd_run: SystemdRun, binding: _CanaryUnitBinding) -> None:
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
    if (
        value != expected
        or (command_ready and code != "ok")
        or (not command_ready and code not in _CANARY_STAGE_CODES)
    ):
        raise _error("runtime_canary_evidence_invalid")
    return code


def _canary_health_payload(image: _CanaryImage) -> Mapping[str, object]:
    """Read one bounded, closed health payload for Canary classification."""

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
        payload = _d320_parse_json(raw)
    except D320CutoverJournalError as exc:
        raise _error("runtime_canary_evidence_invalid") from exc
    if not isinstance(payload, Mapping) or payload.get("schema_version") != 4:
        raise _error("runtime_canary_evidence_invalid")
    checks = payload.get("checks")
    commands = payload.get("commands")
    diagnostics = payload.get("diagnostics")
    keys = {"runtime_status", "hive_status", "hive_doctor"}
    try:
        from the_hive.hive.hourly_probe import valid_probe_record
    except Exception as exc:
        raise _error("runtime_canary_evidence_invalid") from exc
    if (
        not valid_probe_record(payload)
        or payload.get("schema_version") != 4
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
    return payload


def _canary_evidence_result(
    *,
    image: _CanaryImage,
    manager_state: Mapping[str, str],
    payload: Mapping[str, object] | None = None,
) -> tuple[str, str | None]:
    """Classify only the two closed v4 service evidence outcomes."""
    payload = payload if payload is not None else _canary_health_payload(image)
    try:
        from the_hive.hive.hourly_probe import valid_probe_record
    except Exception as exc:
        raise _error("runtime_canary_evidence_invalid") from exc
    if not valid_probe_record(payload) or payload.get("schema_version") != 4:
        raise _error("runtime_canary_evidence_invalid")
    checks = payload["checks"]
    service_checks = payload["service_checks"]
    commands = payload["commands"]
    diagnostics = payload["diagnostics"]
    command_names = {"runtime_status", "hive_status", "hive_doctor"}
    codes = {
        _canary_diagnostic_value(
            diagnostics[name], command_ready=commands[name] is True
        )
        for name in command_names
    }
    expected_checks = {
        "runtime_layout": True,
        "hive_runtime": False,
        "hive_doctor": False,
    }
    alarm = payload["alarm"]
    service_alarm = payload["service_alarm"]
    positive_owner = (
        isinstance(alarm, Mapping)
        and isinstance(service_alarm, Mapping)
        and alarm.get("owner") is not None
        and alarm.get("owner") == service_alarm.get("owner")
    )
    strict_service_checks = {name: True for name in service_checks}
    strict_green = (
        checks == expected_checks
        and service_checks == strict_service_checks
        and payload["global_pilot_readiness"].get("pilot") == "ready"
        and positive_owner
        and all(value is True for value in commands.values())
        and codes == {"ok"}
        and manager_state.get("ActiveState") == "active"
        and manager_state.get("Result") == "success"
        and manager_state.get("ExecMainStatus") == "0"
    )
    if strict_green:
        return "runtime_canary_green", None
    pilot_blocked = (
        checks == expected_checks
        and not all(value is True for value in service_checks.values())
        and payload["global_pilot_readiness"].get("pilot") == "blocked"
        and positive_owner
        and all(value is True for value in commands.values())
        and codes == {"ok"}
        and manager_state.get("ActiveState") == "failed"
        and manager_state.get("Result") == "exit-code"
        and manager_state.get("ExecMainStatus") == "1"
    )
    if pilot_blocked:
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


def _canary_runtime_qualification_status(
    *, image: _CanaryImage, manager_state: Mapping[str, str],
    payload: Mapping[str, object] | None = None,
) -> str:
    """Qualify only strict service-green or exact pilot-blocked v4 evidence."""
    try:
        payload = payload if payload is not None else _canary_health_payload(image)
        status, _error_code = _canary_evidence_result(
            image=image, manager_state=manager_state, payload=payload
        )
    except (RuntimeLifecycleError, D320CutoverJournalError):
        return "fail"
    if status != "runtime_canary_green" or not isinstance(payload, Mapping):
        return "fail"
    checks = payload.get("checks")
    service_checks = payload.get("service_checks")
    commands = payload.get("commands")
    pilot = payload.get("global_pilot_readiness")
    if not all(isinstance(value, Mapping) for value in (checks, service_checks, commands, pilot)):
        return "unknown"
    expected_checks = {
        "runtime_layout": True,
        "hive_runtime": False,
        "hive_doctor": False,
    }
    if (
        checks == expected_checks
        and all(value is True for value in service_checks.values())
        and pilot.get("pilot") == "ready"
        and all(value is True for value in commands.values())
        and manager_state.get("ActiveState") == "active"
        and manager_state.get("Result") == "success"
        and manager_state.get("ExecMainStatus") == "0"
    ):
        return "pass"
    if (
        checks == expected_checks
        and not all(value is True for value in service_checks.values())
        and pilot.get("pilot") == "blocked"
        and all(value is True for value in commands.values())
        and manager_state.get("ActiveState") == "failed"
        and manager_state.get("Result") == "exit-code"
        and manager_state.get("ExecMainStatus") == "1"
    ):
        return "pass"
    return "unknown"


def _canary_runtime_features_qualification_status(
    *, image: _CanaryImage, payload: Mapping[str, object] | None = None
) -> str:
    """Qualify the real runtime surface from a complete v4 owner record."""
    try:
        payload = payload if payload is not None else _canary_health_payload(image)
        from the_hive.hive.hourly_probe import valid_probe_record
        if not valid_probe_record(payload) or payload.get("schema_version") != 4:
            return "fail"
        checks = payload.get("checks")
        service_checks = payload.get("service_checks")
        commands = payload.get("commands")
        diagnostics = payload.get("diagnostics")
        if (
            not isinstance(checks, Mapping)
            or not isinstance(service_checks, Mapping)
            or not isinstance(commands, Mapping)
            or not isinstance(diagnostics, Mapping)
            or checks.get("runtime_layout") is not True
            or service_checks.get("runtime_surface") is not True
            or commands.get("runtime_status") is not True
            or _canary_diagnostic_value(
                diagnostics.get("runtime_status"), command_ready=True
            ) != "ok"
        ):
            return "unknown"
    except (RuntimeLifecycleError, D320CutoverJournalError):
        return "fail"
    return "pass"


def _canary_qualification_diagnostic(
    *,
    payload: Mapping[str, object],
    manager_state: Mapping[str, str],
    evidence_status: str,
    runtime_status: str,
) -> dict[str, object]:
    """Project private Canary evidence into closed, data-sparse diagnostics."""

    check_names = ("runtime_layout", "hive_runtime", "hive_doctor")
    command_names = ("runtime_status", "hive_status", "hive_doctor")
    checks = payload.get("checks")
    commands = payload.get("commands")
    service_checks = payload.get("service_checks")
    pilot = payload.get("global_pilot_readiness")
    if not all(isinstance(value, Mapping) for value in (checks, commands, service_checks, pilot)):
        raise _error("runtime_canary_evidence_invalid")
    failed_checks = sorted(
        name for name in check_names if name in checks and checks[name] is not True
    )
    missing_checks = sorted(name for name in check_names if name not in checks)
    failed_commands = sorted(
        name for name in command_names
        if name in commands and commands[name] is not True
    )
    missing_commands = sorted(name for name in command_names if name not in commands)
    checks_all_true = not failed_checks and not missing_checks
    commands_all_true = not failed_commands and not missing_commands
    strict_unit_success = (
        manager_state.get("ActiveState") == "active"
        and manager_state.get("Result") == "success"
        and manager_state.get("ExecMainStatus") == "0"
    )
    failed_exit_code = (
        manager_state.get("ActiveState") == "failed"
        and manager_state.get("Result") == "exit-code"
        and manager_state.get("ExecMainStatus") == "1"
    )
    unit_state_class = (
        "active_success_0"
        if strict_unit_success
        else "failed_exit_code_1"
        if failed_exit_code
        else "other"
    )
    expected_checks = {
        "runtime_layout": True,
        "hive_runtime": False,
        "hive_doctor": False,
    }
    if evidence_status == "runtime_canary_red":
        evidence_case = "stage_red"
    elif (
        evidence_status == "runtime_canary_green"
        and checks == expected_checks
        and all(value is True for value in service_checks.values())
        and pilot.get("pilot") == "ready"
        and commands_all_true
        and strict_unit_success
    ):
        evidence_case = "service_green"
    elif (
        evidence_status == "runtime_canary_green"
        and checks == expected_checks
        and not all(value is True for value in service_checks.values())
        and pilot.get("pilot") == "blocked"
        and commands_all_true
        and failed_exit_code
    ):
        evidence_case = "pilot_blocked_green"
    elif checks_all_true and commands_all_true and strict_unit_success:
        evidence_case = "strict_green"
    else:
        raise _error("runtime_canary_evidence_invalid")
    reasons: set[str] = set()
    if evidence_case == "stage_red":
        reasons.add("canary_evidence_red")
    if not checks_all_true:
        reasons.add("health_checks_not_all_true")
    if not commands_all_true:
        reasons.add("health_commands_not_all_true")
    if not strict_unit_success:
        reasons.add("unit_not_strict_success")
    if runtime_status == "fail" and evidence_case != "stage_red":
        reasons.add("runtime_qualification_failed")
    if runtime_status == "unknown" and not reasons:
        reasons.add("runtime_qualification_unknown")
    return {
        "evidence_case": evidence_case,
        "runtime_status": runtime_status,
        "runtime_reasons": sorted(reasons),
        "checks_all_true": checks_all_true,
        "commands_all_true": commands_all_true,
        "failed_checks": failed_checks,
        "missing_checks": missing_checks,
        "failed_commands": failed_commands,
        "missing_commands": missing_commands,
        "unit_state_class": unit_state_class,
    }


def _probe_codex_client_metadata(
    *, executable: Path, home: Path, codex_home: Path
) -> dict[str, object]:
    """Observe CLI metadata and config readback through one pinned executable FD.

    The differential config probe checks only the structural `--no-daemon`
    consumer contract. It does not establish runtime behavior or G5 support.
    """

    source_fd = snapshot_fd = codex_fd = config_fd = -1
    try:
        for directory in (home, codex_home):
            info = directory.lstat()
            if (
                stat.S_ISLNK(info.st_mode)
                or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700
            ):
                raise _error("runtime_canary_client_probe_invalid")
        if codex_home.parent != home or codex_home.name != ".codex":
            raise _error("runtime_canary_client_probe_invalid")
        path_info = executable.lstat()
        if (
            stat.S_ISLNK(path_info.st_mode)
            or not stat.S_ISREG(path_info.st_mode)
            or path_info.st_uid not in {0, os.geteuid()}
            or path_info.st_nlink != 1
            or path_info.st_mode & 0o022
            or not os.access(executable, os.X_OK)
        ):
            raise _error("runtime_canary_client_probe_invalid")
        source_fd = os.open(
            executable,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        pinned = os.fstat(source_fd)
        current = executable.lstat()
        if (
            not stat.S_ISREG(pinned.st_mode)
            or pinned.st_nlink != 1
            or pinned.st_uid not in {0, os.geteuid()}
            or pinned.st_mode & 0o022
            or (pinned.st_dev, pinned.st_ino) != (current.st_dev, current.st_ino)
            or pinned.st_size <= 0
            or pinned.st_size > 512 * 1024 * 1024
        ):
            raise _error("runtime_canary_client_probe_invalid")
        snapshot_fd = os.memfd_create(
            "the-hive-codex-probe",
            getattr(os, "MFD_CLOEXEC", 0) | getattr(os, "MFD_ALLOW_SEALING", 0),
        )
        digest = hashlib.sha256()
        offset = 0
        while offset < pinned.st_size:
            chunk = os.pread(
                source_fd, min(1024 * 1024, pinned.st_size - offset), offset
            )
            if not chunk:
                raise _error("runtime_canary_client_probe_invalid")
            digest.update(chunk)
            written = 0
            while written < len(chunk):
                written += os.write(snapshot_fd, chunk[written:])
            offset += len(chunk)
        if os.fstat(source_fd).st_size != pinned.st_size:
            raise _error("runtime_canary_client_probe_invalid")
        os.fchmod(snapshot_fd, 0o500)
        seals = (
            getattr(fcntl, "F_SEAL_SEAL", 0)
            | getattr(fcntl, "F_SEAL_SHRINK", 0)
            | getattr(fcntl, "F_SEAL_GROW", 0)
            | getattr(fcntl, "F_SEAL_WRITE", 0)
        )
        if not seals:
            raise _error("runtime_canary_client_probe_invalid")
        fcntl.fcntl(snapshot_fd, fcntl.F_ADD_SEALS, seals)
        os.close(source_fd)
        source_fd = -1
        environment = {
            "CODEX_HOME": os.fspath(codex_home),
            "HOME": os.fspath(home),
            "LANG": "C",
            "PATH": "/usr/bin:/bin",
        }
        codex_info = codex_home.lstat()
        codex_fd = os.open(
            codex_home,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        opened_codex = os.fstat(codex_fd)
        if (
            (opened_codex.st_dev, opened_codex.st_ino)
            != (codex_info.st_dev, codex_info.st_ino)
            or opened_codex.st_uid != os.geteuid()
            or stat.S_IMODE(opened_codex.st_mode) != 0o700
        ):
            raise _error("runtime_canary_client_probe_invalid")
        config_fd = os.open(
            "config.toml",
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=codex_fd,
        )
        os.fchmod(config_fd, 0o600)
        config_identity = os.fstat(config_fd)
        if (
            not stat.S_ISREG(config_identity.st_mode)
            or config_identity.st_uid != os.geteuid()
            or config_identity.st_nlink != 1
            or stat.S_IMODE(config_identity.st_mode) != 0o600
        ):
            raise _error("runtime_canary_client_probe_invalid")

        def read_back_config(expected: bytes) -> str:
            current_parent = os.stat(".", dir_fd=codex_fd, follow_symlinks=False)
            parent_path = codex_home.lstat()
            named = os.stat("config.toml", dir_fd=codex_fd, follow_symlinks=False)
            opened = os.fstat(config_fd)
            if (
                (current_parent.st_dev, current_parent.st_ino)
                != (opened_codex.st_dev, opened_codex.st_ino)
                or (parent_path.st_dev, parent_path.st_ino)
                != (opened_codex.st_dev, opened_codex.st_ino)
                or (named.st_dev, named.st_ino)
                != (config_identity.st_dev, config_identity.st_ino)
                or (opened.st_dev, opened.st_ino, opened.st_size)
                != (config_identity.st_dev, config_identity.st_ino, len(expected))
                or opened.st_uid != os.geteuid()
                or opened.st_nlink != 1
                or stat.S_IMODE(opened.st_mode) != 0o600
                or os.pread(config_fd, len(expected) + 1, 0) != expected
            ):
                raise _error("runtime_canary_client_probe_invalid")
            return hashlib.sha256(expected).hexdigest()

        def observe_feature_value(value: bool) -> tuple[bool, str, str, str] | None:
            config = (
                b"[features]\ndaemon_auto_start = true\n"
                if value
                else b"[features]\ndaemon_auto_start = false\n"
            )
            os.ftruncate(config_fd, 0)
            offset = 0
            while offset < len(config):
                offset += os.pwrite(config_fd, config[offset:], offset)
            os.fsync(config_fd)
            config_sha256 = read_back_config(config)
            response = _run_pinned_client_command(
                snapshot_fd,
                ("--no-daemon", "features", "list"),
                cwd=home,
                environment=environment,
            )
            if response is None:
                return None
            read_back_config(config)
            matches = [
                line.strip()
                for line in response.splitlines()
                if line.split()[:1] == ["daemon_auto_start"]
            ]
            if len(matches) != 1:
                return None
            fields = matches[0].split()
            if len(fields) != 3 or fields[1] != "stable":
                return None
            parsed = fields[2] == "true" if fields[2] in {"true", "false"} else None
            if parsed is None or parsed is not value:
                return None
            if (
                os.fstat(config_fd).st_size != len(config)
                or os.pread(config_fd, len(config) + 1, 0) != config
            ):
                return None
            return (
                parsed,
                config_sha256,
                hashlib.sha256(matches[0].encode("utf-8")).hexdigest(),
                hashlib.sha256(response.encode("utf-8")).hexdigest(),
            )

        version = _run_pinned_client_command(
            snapshot_fd, ("--version",), cwd=home, environment=environment
        )
        false_probe = observe_feature_value(False)
        true_probe = observe_feature_value(True)
        parent_after = codex_home.lstat()
        if (parent_after.st_dev, parent_after.st_ino) != (
            opened_codex.st_dev,
            opened_codex.st_ino,
        ):
            raise _error("runtime_canary_client_probe_invalid")
        compatibility_probe = None
        if false_probe is not None and true_probe is not None:
            compatibility_probe = {
                "argv": ["--no-daemon", "features", "list"],
                "config_sha256": {
                    "false": false_probe[1],
                    "true": true_probe[1],
                },
                "exit_codes": {"false": 0, "true": 0},
                "expected": {"false": False, "true": True},
                "observed": {
                    "false": false_probe[0],
                    "true": true_probe[0],
                },
                "readback_line_sha256": {
                    "false": false_probe[2],
                    "true": true_probe[2],
                },
                "response_sha256": {
                    "false": false_probe[3],
                    "true": true_probe[3],
                },
                "schema_revision": 1,
            }
        return {
            "artifact_sha256": digest.hexdigest(),
            "compatibility_probe": compatibility_probe,
            "features_sha256": (
                hashlib.sha256(
                    _d320_canonical_json(
                        {
                            "false": false_probe[3],
                            "true": true_probe[3],
                        }
                    )
                ).hexdigest()
                if false_probe is not None and true_probe is not None
                else None
            ),
            "features_status": (
                "observed"
                if false_probe is not None and true_probe is not None
                else "unknown"
            ),
            "version": version,
            "version_status": "observed" if version is not None else "unknown",
            "no_daemon_status": (
                "pass" if compatibility_probe is not None else "unknown"
            ),
            "config_readback_status": (
                "pass" if compatibility_probe is not None else "unknown"
            ),
        }
    except (OSError, RuntimeLifecycleError):
        return {
            "artifact_sha256": None,
            "features": None,
            "features_status": "unknown",
            "compatibility_probe": None,
            "version": None,
            "version_status": "unknown",
            "no_daemon_status": "unknown",
            "config_readback_status": "unknown",
        }
    finally:
        for descriptor in (source_fd, snapshot_fd, config_fd, codex_fd):
            if descriptor >= 0:
                os.close(descriptor)


def _canonical_codex_client_path() -> Path | None:
    """Resolve only the fixed, root-owned Codex installation used by Hive."""

    try:
        wrapper_link = _CANONICAL_CODEX_WRAPPER
        link_info = wrapper_link.lstat()
        wrapper = wrapper_link.resolve(strict=True)
        wrapper_info = wrapper.lstat()
        if (
            not stat.S_ISLNK(link_info.st_mode)
            or link_info.st_uid != 0
            or not stat.S_ISREG(wrapper_info.st_mode)
            or wrapper_info.st_uid != 0
            or wrapper_info.st_nlink != 1
            or wrapper_info.st_mode & 0o022
            or wrapper.name != "codex.js"
            or wrapper.parent.name != "bin"
            or wrapper.parents[1].name != "codex"
            or wrapper.parents[2].name != "@openai"
            or wrapper.parents[3].name != "node_modules"
        ):
            return None
        current = wrapper_link.parent
        while current != Path("/"):
            info = current.lstat()
            if (
                stat.S_ISLNK(info.st_mode)
                or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != 0
                or info.st_mode & 0o022
            ):
                return None
            current = current.parent
        platform_key = (os.uname().sysname, os.uname().machine)
        package, target = {
            ("Linux", "x86_64"): ("codex-linux-x64", "x86_64-unknown-linux-musl"),
            ("Linux", "aarch64"): ("codex-linux-arm64", "aarch64-unknown-linux-musl"),
        }[platform_key]
        executable = (
            wrapper.parents[1]
            / "node_modules"
            / "@openai"
            / package
            / "vendor"
            / target
            / "bin"
            / "codex"
        )
        current = executable
        while current != Path("/"):
            info = current.lstat()
            if (
                stat.S_ISLNK(info.st_mode)
                or info.st_uid != 0
                or info.st_mode & 0o022
                or (current != executable and not stat.S_ISDIR(info.st_mode))
            ):
                return None
            current = current.parent
        info = executable.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or not info.st_mode & 0o111
        ):
            return None
        latest_link = wrapper_link.lstat()
        if (latest_link.st_dev, latest_link.st_ino) != (
            link_info.st_dev,
            link_info.st_ino,
        ) or wrapper_link.resolve(strict=True) != wrapper:
            return None
        return executable
    except (OSError, KeyError, IndexError, AttributeError):
        return None


def _canonical_codex_client_digest() -> str | None:
    executable = _canonical_codex_client_path()
    if executable is None:
        return None
    descriptor = -1
    try:
        before = executable.lstat()
        descriptor = os.open(
            executable,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != 0
            or opened.st_nlink != 1
            or opened.st_mode & 0o022
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            or opened.st_size <= 0
            or opened.st_size > 512 * 1024 * 1024
        ):
            return None
        digest = hashlib.sha256()
        offset = 0
        while offset < opened.st_size:
            chunk = os.pread(
                descriptor, min(1024 * 1024, opened.st_size - offset), offset
            )
            if not chunk:
                return None
            digest.update(chunk)
            offset += len(chunk)
        after = os.fstat(descriptor)
        latest = executable.lstat()
        if (after.st_dev, after.st_ino, after.st_size) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
        ) or (latest.st_dev, latest.st_ino) != (opened.st_dev, opened.st_ino):
            return None
        return digest.hexdigest()
    except OSError:
        return None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _canary_client_metadata(invocation: Path) -> Mapping[str, object] | None:
    executable = _canonical_codex_client_path()
    if executable is None:
        return None
    home = invocation / "client-home"
    codex_home = home / ".codex"
    try:
        home.mkdir(mode=0o700)
        codex_home.mkdir(mode=0o700)
        _private_directory(home)
        _private_directory(codex_home)
        observation = _probe_codex_client_metadata(
            executable=executable, home=home, codex_home=codex_home
        )
        if (
            observation["version_status"] != "observed"
            or observation["features_status"] != "observed"
            or not isinstance(observation["artifact_sha256"], str)
            or not isinstance(observation["features_sha256"], str)
            or not _valid_client_compatibility_probe(
                observation.get("compatibility_probe")
            )
        ):
            return None
        return {
            "artifact_sha256": observation["artifact_sha256"],
            "compatibility_probe": observation["compatibility_probe"],
            "features_sha256": observation["features_sha256"],
            "version": observation["version"],
        }
    except (OSError, RuntimeLifecycleError):
        return None


def _valid_client_compatibility_probe(value: object) -> bool:
    if not isinstance(value, Mapping) or set(value) != {
        "argv",
        "config_sha256",
        "exit_codes",
        "expected",
        "observed",
        "readback_line_sha256",
        "response_sha256",
        "schema_revision",
    }:
        return False
    config_sha256 = value.get("config_sha256")
    readback = value.get("readback_line_sha256")
    responses = value.get("response_sha256")
    return (
        value.get("schema_revision") == 1
        and value.get("argv") == ["--no-daemon", "features", "list"]
        and value.get("exit_codes") == {"false": 0, "true": 0}
        and value.get("expected") == {"false": False, "true": True}
        and value.get("observed") == {"false": False, "true": True}
        and isinstance(config_sha256, Mapping)
        and set(config_sha256) == {"false", "true"}
        and all(
            isinstance(config_sha256.get(key), str)
            and re.fullmatch(_SHA256_HEX_PATTERN, config_sha256[key])
            for key in ("false", "true")
        )
        and isinstance(readback, Mapping)
        and set(readback) == {"false", "true"}
        and all(
            isinstance(readback.get(key), str)
            and re.fullmatch(_SHA256_HEX_PATTERN, readback[key])
            for key in ("false", "true")
        )
        and isinstance(responses, Mapping)
        and set(responses) == {"false", "true"}
        and all(
            isinstance(responses.get(key), str)
            and re.fullmatch(_SHA256_HEX_PATTERN, responses[key])
            for key in ("false", "true")
        )
    )


def _canary_manager_state_snapshot(
    systemctl: Systemctl,
) -> dict[str, dict[str, str]] | None:
    """Read the six cutover units without attributing behavior to their manager."""

    try:
        return {unit: dict(_show(systemctl, unit)) for unit in _V2_MANAGER_UNITS}
    except RuntimeLifecycleError:
        return None
    except Exception:
        return None


def _manager_api_contract_snapshot() -> dict[str, object] | None:
    """Observe the real user manager API through its pinned bus socket.

    This records interface availability only. It does not claim permission or
    successful execution of manager actions.
    """

    runtime_directory = _user_runtime_directory()
    bus_path = runtime_directory / "bus"
    runtime_fd = bus_fd = -1
    try:
        _private_directory(runtime_directory)
        runtime_before = runtime_directory.lstat()
        runtime_fd = os.open(
            runtime_directory,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        runtime_info = os.fstat(runtime_fd)
        if (runtime_info.st_dev, runtime_info.st_ino) != (
            runtime_before.st_dev,
            runtime_before.st_ino,
        ):
            return None
        bus_before = os.stat("bus", dir_fd=runtime_fd, follow_symlinks=False)
        if (
            not stat.S_ISSOCK(bus_before.st_mode)
            or bus_before.st_uid != os.geteuid()
            or bus_before.st_nlink != 1
        ):
            return None
        bus_fd = os.open(
            "bus",
            getattr(os, "O_PATH", os.O_RDONLY)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            dir_fd=runtime_fd,
        )
        bus_info = os.fstat(bus_fd)
        if (bus_info.st_dev, bus_info.st_ino) != (
            bus_before.st_dev,
            bus_before.st_ino,
        ):
            return None
        address = f"unix:path=/proc/self/fd/{bus_fd}"
        environment = {
            "DBUS_SESSION_BUS_ADDRESS": address,
            "LANG": "C",
            "PATH": "/usr/bin:/bin",
            "XDG_RUNTIME_DIR": os.fspath(runtime_directory),
        }

        def run(arguments: list[str], maximum: int) -> str | None:
            try:
                completed = subprocess.run(
                    arguments,
                    check=False,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    timeout=8,
                    env=environment,
                    pass_fds=(bus_fd,),
                )
            except (OSError, subprocess.SubprocessError):
                return None
            if completed.returncode != 0 or len(completed.stdout) > maximum:
                return None
            try:
                return completed.stdout.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                return None

        manager_text = run(
            [
                "/usr/bin/systemctl",
                "--user",
                "--no-pager",
                "show",
                "--property=Version,Features,UnitPath",
            ],
            16 * 1024,
        )
        if manager_text is None:
            return None
        manager = dict(
            line.split("=", 1) for line in manager_text.splitlines() if "=" in line
        )
        unit_paths = manager.get("UnitPath", "").split()
        if (
            not manager.get("Version")
            or not manager.get("Features")
            or not unit_paths
            or any(not os.path.isabs(path) for path in unit_paths)
        ):
            return None
        unit_path_rows: list[dict[str, object]] = []
        for path in unit_paths:
            try:
                path_info = os.lstat(path)
            except FileNotFoundError:
                unit_path_rows.append(
                    {"dev": None, "ino": None, "mode": None, "path": path, "uid": None}
                )
            except OSError:
                return None
            else:
                if stat.S_ISLNK(path_info.st_mode) or not stat.S_ISDIR(
                    path_info.st_mode
                ):
                    return None
                unit_path_rows.append(
                    {
                        "dev": path_info.st_dev,
                        "ino": path_info.st_ino,
                        "mode": stat.S_IMODE(path_info.st_mode),
                        "path": path,
                        "uid": path_info.st_uid,
                    }
                )
        owner_text = run(
            ["/usr/bin/busctl", "--user", "status", "org.freedesktop.systemd1"],
            8 * 1024,
        )
        introspection = run(
            [
                "/usr/bin/busctl",
                "--user",
                "introspect",
                "org.freedesktop.systemd1",
                "/org/freedesktop/systemd1",
                "org.freedesktop.systemd1.Manager",
            ],
            64 * 1024,
        )
        if owner_text is None or introspection is None:
            return None
        owner = dict(
            line.split("=", 1) for line in owner_text.splitlines() if "=" in line
        )
        if (
            owner.get("UID") != str(os.geteuid())
            or owner.get("OwnerUID") != str(os.geteuid())
            or not owner.get("UniqueName", "").startswith(":")
            or not owner.get("PID", "").isdigit()
            or not owner.get("Unit")
            or not owner.get("CGroup")
        ):
            return None
        required_signatures = {
            "Reload": ("-", "-"),
            "StartUnit": ("ss", "o"),
            "StopUnit": ("ss", "o"),
            "EnableUnitFiles": ("asbb", "ba(sss)"),
            "DisableUnitFiles": ("asb", "a(sss)"),
            "GetUnitFileState": ("s", "s"),
        }
        found: dict[str, tuple[str, str]] = {}
        for line in introspection.splitlines()[1:]:
            fields = line.split()
            if len(fields) >= 4 and fields[1] == "method":
                found[fields[0].lstrip(".")] = (fields[2], fields[3])
        if any(
            found.get(name) != signature
            for name, signature in required_signatures.items()
        ):
            return None
        current_runtime = runtime_directory.lstat()
        current_runtime_fd = os.fstat(runtime_fd)
        current_bus = os.stat("bus", dir_fd=runtime_fd, follow_symlinks=False)
        current_bus_path = bus_path.lstat()
        current_fd = os.fstat(bus_fd)
        if (
            (current_runtime.st_dev, current_runtime.st_ino)
            != (
                runtime_info.st_dev,
                runtime_info.st_ino,
            )
            or (current_runtime_fd.st_dev, current_runtime_fd.st_ino)
            != (
                runtime_info.st_dev,
                runtime_info.st_ino,
            )
            or (current_bus.st_dev, current_bus.st_ino)
            != (
                bus_info.st_dev,
                bus_info.st_ino,
            )
            or (current_bus_path.st_dev, current_bus_path.st_ino)
            != (
                bus_info.st_dev,
                bus_info.st_ino,
            )
            or (current_fd.st_dev, current_fd.st_ino)
            != (
                bus_info.st_dev,
                bus_info.st_ino,
            )
        ):
            return None
        current_unit_path_rows: list[dict[str, object]] = []
        for path in unit_paths:
            try:
                path_info = os.lstat(path)
            except FileNotFoundError:
                current_unit_path_rows.append(
                    {"dev": None, "ino": None, "mode": None, "path": path, "uid": None}
                )
            except OSError:
                return None
            else:
                if stat.S_ISLNK(path_info.st_mode) or not stat.S_ISDIR(
                    path_info.st_mode
                ):
                    return None
                current_unit_path_rows.append(
                    {
                        "dev": path_info.st_dev,
                        "ino": path_info.st_ino,
                        "mode": stat.S_IMODE(path_info.st_mode),
                        "path": path,
                        "uid": path_info.st_uid,
                    }
                )
        if current_unit_path_rows != unit_path_rows:
            return None
        return {
            "bus": {
                "dev": bus_info.st_dev,
                "ino": bus_info.st_ino,
                "mode": stat.S_IMODE(bus_info.st_mode),
                "uid": bus_info.st_uid,
            },
            "owner": {
                key: owner[key]
                for key in ("CGroup", "OwnerUID", "PID", "Unit", "UID", "UniqueName")
            },
            "manager": {
                "features_sha256": hashlib.sha256(
                    manager["Features"].encode("utf-8")
                ).hexdigest(),
                "version": manager["Version"],
            },
            "unit_paths": unit_path_rows,
            "unit_path_sha256": hashlib.sha256(
                _d320_canonical_json(unit_path_rows)
            ).hexdigest(),
            "api_sha256": hashlib.sha256(
                _d320_canonical_json(
                    {
                        name: list(required_signatures[name])
                        for name in sorted(required_signatures)
                    }
                )
            ).hexdigest(),
        }
    except (OSError, D320CutoverJournalError, ValueError):
        return None
    finally:
        if bus_fd >= 0:
            os.close(bus_fd)
        if runtime_fd >= 0:
            os.close(runtime_fd)


def _run_pinned_client_command(
    executable_fd: int,
    arguments: tuple[str, ...],
    *,
    cwd: Path,
    environment: Mapping[str, str],
) -> str | None:
    """Run one metadata command through the exact inherited executable FD."""

    process: subprocess.Popen[bytes] | None = None
    selector: selectors.BaseSelector | None = None
    output = bytearray()
    try:
        process = subprocess.Popen(
            [f"/proc/self/fd/{executable_fd}", *arguments],
            cwd=cwd,
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            pass_fds=(executable_fd,),
            start_new_session=True,
        )
        assert process.stdout is not None and process.stderr is not None
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        selector.register(process.stderr, selectors.EVENT_READ)
        deadline = time.monotonic() + _CANARY_CLIENT_COMMAND_SECONDS
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            for key, _mask in selector.select(min(remaining, 0.2)):
                chunk = os.read(key.fileobj.fileno(), 4096)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                if key.fileobj is process.stdout:
                    if len(output) + len(chunk) > _CANARY_CLIENT_OUTPUT_BYTES:
                        raise ValueError("client probe output exceeded limit")
                    output.extend(chunk)
        if process.wait(timeout=max(0.0, deadline - time.monotonic())) != 0:
            return None
        text = output.decode("utf-8", errors="strict").strip()
        return text if text and len(text) <= _CANARY_CLIENT_OUTPUT_BYTES else None
    except (
        OSError,
        subprocess.SubprocessError,
        TimeoutError,
        UnicodeError,
        ValueError,
    ):
        return None
    finally:
        if selector is not None:
            selector.close()
        if process is not None and process.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            with contextlib.suppress(subprocess.SubprocessError):
                process.wait(timeout=1)


def _valid_bound_unit_state(state: Mapping[str, str]) -> bool:
    """Accept only states for which rollback has a defined, safe operation."""

    load = state.get("LoadState")
    unit_file = state.get("UnitFileState")
    active = state.get("ActiveState")
    if load == "not-found":
        return unit_file in {"", "disabled"} and active == "inactive"
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

    Every service not bound as active is quiesced. The caller then observes
    the manager and resets only a failure record that actually exists; an
    unconditional reset fails for valid inactive units absent from manager
    memory.
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
        return (("stop", unit),)
    return (("start", unit),) if _state_is_active(state) else (("stop", unit),)


def _restored_state_target(unit: str, state: Mapping[str, str]) -> Mapping[str, str]:
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


def _parse_health(
    state_root: Path,
) -> tuple[bool, bool, bool, bool, bool, bool]:
    """Return one validated record's legacy, service and gate projections."""
    try:
        raw = _regular_bytes(
            state_root / "hive-hourly-health.json",
            maximum=_MAX_HEALTH_BYTES,
            mode=0o600,
        )
        if raw is None:
            return False, False, False, False, False, False
        value = _d320_parse_json(raw)
    except (RuntimeLifecycleError, D320CutoverJournalError):
        return False, False, False, False, False, False
    try:
        from the_hive.hive.hourly_probe import probe_spawn_gate, valid_probe_record
    except Exception:
        return False, False, False, False, False, False
    if not valid_probe_record(value):
        return False, False, False, False, False, False
    checks = value.get("checks")
    alarm = value.get("alarm")
    legacy_green = checks == {
        "runtime_layout": True,
        "hive_runtime": True,
        "hive_doctor": True,
    }
    legacy_alarm = (
        isinstance(alarm, Mapping)
        and alarm.get("scope") == "hive"
        and alarm.get("status") == "cleared"
        and alarm.get("reason_codes") == []
    )
    service_checks = value.get("service_checks")
    service_alarm = value.get("service_alarm")
    service_green = (
        value.get("schema_version") == 4
        and isinstance(service_checks, Mapping)
        and frozenset(service_checks)
        == {"runtime_surface", "configuration", "repository", "principals", "state", "usage"}
        and all(item is True for item in service_checks.values())
    )
    service_alarm_cleared = (
        isinstance(service_alarm, Mapping)
        and service_alarm.get("scope") == "hive"
        and service_alarm.get("status") == "cleared"
        and service_alarm.get("reason_codes") == []
    )
    gate_allowed = probe_spawn_gate(value).get("allowed") is True
    return True, legacy_green, legacy_alarm, service_green, service_alarm_cleared, gate_allowed


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
            "consumer_sha256": hashlib.sha256(consumer).hexdigest(),
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


def _revalidate_v2_predecessor(
    release_root: Path, expected: Mapping[str, object]
) -> None:
    """Re-read the attested runtime consumer before using journaled predecessor data."""

    actual = _runtime_identity(release_root)
    if (
        not isinstance(actual, Mapping)
        or actual.get("consumer_pin") is not True
        or any(
            actual.get(name) != expected.get(name)
            for name in ("generation", "manifest_digest", "consumer_sha256")
        )
    ):
        raise _error("runtime_lifecycle_predecessor_changed")


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
    binding: _ProbeObservationBinding, *, observed_at: datetime, returncode: int
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
                "returncode": returncode,
                "schema_version": 1,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _write_observation(
    state_root: Path, binding: _ProbeObservationBinding, *, returncode: int
) -> None:
    """Atomically record one structurally valid bounded launcher invocation."""

    _regular_bytes(
        state_root / _OBSERVATION_NAME,
        maximum=_MAX_OBSERVATION_BYTES,
        mode=0o600,
    )
    _atomic_restore(
        state_root / _OBSERVATION_NAME,
        _observation_payload(
            binding, observed_at=datetime.now(UTC), returncode=returncode
        ),
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
            and value.get("returncode") in {0, 1}
            and age >= 0
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
    started_at = datetime.now(UTC)
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
    finished_at = datetime.now(UTC)
    if result.returncode not in {0, 1}:
        raise _error("runtime_lifecycle_probe_failed")
    try:
        from the_hive.hive.hourly_probe import probe_spawn_gate, valid_probe_record

        health_raw = _regular_bytes(
            state_root / "hive-hourly-health.json",
            maximum=_MAX_HEALTH_BYTES,
            mode=0o600,
        )
        health = (
            json.loads(health_raw.decode("utf-8")) if health_raw is not None else None
        )
        checked_at_raw = (
            health.get("checked_at") if isinstance(health, Mapping) else None
        )
        checked_at = (
            datetime.fromisoformat(checked_at_raw.replace("Z", "+00:00"))
            if isinstance(checked_at_raw, str)
            else None
        )
        expected_returncode = (
            0
            if probe_spawn_gate(health, now=finished_at).get("allowed") is True
            else 1
        )
        if (
            not valid_probe_record(health)
            or checked_at is None
            or checked_at.tzinfo is None
            or checked_at.utcoffset() is None
            or checked_at.astimezone(UTC) < started_at
            or checked_at.astimezone(UTC) > finished_at
            or result.returncode != expected_returncode
        ):
            raise _error("runtime_lifecycle_probe_result_invalid")
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise _error("runtime_lifecycle_probe_result_invalid") from exc
    current = _runtime_identity(release_root)
    if current is None or current.get("consumer_pin") is not True:
        raise _error("runtime_lifecycle_probe_binding_changed")
    rebound = _probe_observation_binding(
        home=home, release_root=release_root, identity=current
    )
    if rebound != binding:
        raise _error("runtime_lifecycle_probe_binding_changed")
    _write_observation(state_root, rebound, returncode=result.returncode)


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
    if getattr(evidence, "status", None) not in {"complete", "partial", "stale"} or len(
        authorities
    ) != len(expected):
        return False
    observed = [
        (
            getattr(item, "account_id", None),
            getattr(item, "pool_id", None),
            getattr(item, "provider", None),
            tuple(getattr(item, "allowed_model_families", ())),
            getattr(item, "reasoning_minimum", None),
            getattr(item, "reasoning_maximum", None),
            tuple(getattr(item, "allowed_lifecycles", ())),
        )
        for item in authorities
    ]
    expected_records = [
        (
            account,
            "openai",
            "openai",
            ("luna", "sol", "terra"),
            "low",
            "max",
            ("ephemeral", "persistent", "session"),
        )
        for account in expected
    ]
    if sorted(observed) != sorted(expected_records):
        return False
    for item in authorities:
        available = getattr(item, "hive_available", None)
        persistent = getattr(item, "persistent_leadership_eligible", None)
        long_running = getattr(item, "long_running_leadership_eligible", None)
        if any(
            type(value) is not bool for value in (available, persistent, long_running)
        ):
            return False
        if (persistent or long_running) and not available:
            return False
        if long_running and not persistent:
            return False
    return True


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
            "health_v3_valid": False,
            "argumentless_probe_observed": False,
        },
        "product_status": "blocked",
        "product_checks": {
            "health_v3_green": False,
            "queen_alarm_cleared": False,
            "probe_gate_allowed": False,
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
        ("health_record_valid", "runtime_lifecycle_health_invalid"),
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
    health_valid, health_v3_green, legacy_alarm_cleared, service_green, service_alarm_cleared, gate_allowed = _parse_health(state_root)
    v2 = _d296_and_v2_accepted()
    enabled, active = _state_is_enabled(timer_state), _state_is_active(timer_state)
    observed = _observation_matches(home=home, state_root=state_root, identity=identity)
    checks = {
        "runtime_attested": runtime,
        "unit_files": unit_files,
        "eight_utc_terms": eight,
        "no_legacy_or_duplicate_timer": no_old,
        "v2_generation_and_d296_parity": v2,
        "health_record_valid": health_valid,
        "argumentless_probe_observed": observed,
    }
    product_checks = {
        "service_probe_green": service_green,
        "service_alarm_cleared": service_alarm_cleared,
        "probe_gate_allowed": gate_allowed,
    }
    legacy_product_checks = {
        "health_v3_green": health_v3_green,
        "queen_alarm_cleared": legacy_alarm_cleared,
    }
    all_green = all(checks.values()) and enabled and active and observed
    service_ready = all(product_checks.values())
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
        "product_status": "service_ready_request_required" if service_ready else "blocked",
        "product_checks": product_checks,
        "legacy_product_checks": legacy_product_checks,
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


def _target_binding(home: Path) -> dict[str, object]:
    info = home.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
    ):
        raise _error("runtime_lifecycle_target_invalid")
    return {
        "realpath": str(home.resolve(strict=True)),
        "dev": info.st_dev,
        "ino": info.st_ino,
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": stat.S_IMODE(info.st_mode),
    }


def _manager_states_digest(states: object) -> str | None:
    if not isinstance(states, Mapping):
        return None
    try:
        return hashlib.sha256(_d320_canonical_json(dict(states))).hexdigest()
    except D320CutoverJournalError:
        return None


def _valid_manager_api_contract(value: object) -> bool:
    if not isinstance(value, Mapping) or set(value) != {
        "api_sha256",
        "bus",
        "manager",
        "owner",
        "unit_paths",
        "unit_path_sha256",
    }:
        return False
    bus = value.get("bus")
    manager = value.get("manager")
    owner = value.get("owner")
    return bool(
        isinstance(bus, Mapping)
        and set(bus) == {"dev", "ino", "mode", "uid"}
        and all(type(bus.get(key)) is int for key in ("dev", "ino", "mode", "uid"))
        and isinstance(manager, Mapping)
        and set(manager) == {"features_sha256", "version"}
        and isinstance(manager.get("features_sha256"), str)
        and re.fullmatch(_SHA256_HEX_PATTERN, manager["features_sha256"])
        and isinstance(manager.get("version"), str)
        and bool(manager["version"])
        and isinstance(owner, Mapping)
        and set(owner) == {"CGroup", "OwnerUID", "PID", "Unit", "UID", "UniqueName"}
        and all(isinstance(owner.get(key), str) and owner[key] for key in owner)
        and owner["PID"].isdigit()
        and owner["UID"].isdigit()
        and owner["OwnerUID"].isdigit()
        and owner["OwnerUID"] == owner["UID"]
        and owner["UniqueName"].startswith(":")
        and isinstance(value.get("unit_paths"), list)
        and bool(value["unit_paths"])
        and all(
            isinstance(item, Mapping)
            and set(item) == {"dev", "ino", "mode", "path", "uid"}
            and isinstance(item.get("path"), str)
            and os.path.isabs(item["path"])
            and all(
                item.get(key) is None or type(item.get(key)) is int
                for key in ("dev", "ino", "mode", "uid")
            )
            and (
                all(item.get(key) is None for key in ("dev", "ino", "mode", "uid"))
                or all(
                    type(item.get(key)) is int for key in ("dev", "ino", "mode", "uid")
                )
            )
            for item in value["unit_paths"]
        )
        and isinstance(value.get("unit_path_sha256"), str)
        and re.fullmatch(_SHA256_HEX_PATTERN, value["unit_path_sha256"])
        and value["unit_path_sha256"]
        == hashlib.sha256(_d320_canonical_json(value["unit_paths"])).hexdigest()
        and isinstance(value.get("api_sha256"), str)
        and re.fullmatch(_SHA256_HEX_PATTERN, value["api_sha256"])
    )


def _canary_runtime_root() -> Path:
    return _user_runtime_directory() / _CANARY_RUNTIME_ROOT_NAME


def _read_canary_qualification_record(root: Path) -> Mapping[str, object] | None:
    """Read one existing qualification record under the Canary owner's SH lock."""

    root_fd = lock_fd = record_fd = -1
    try:
        try:
            root_info = root.lstat()
        except FileNotFoundError:
            return None
        _private_directory(root)
        root_fd = os.open(
            root,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        opened_root = os.fstat(root_fd)
        if (opened_root.st_dev, opened_root.st_ino) != (
            root_info.st_dev,
            root_info.st_ino,
        ):
            raise _error("runtime_lifecycle_qualification_record_invalid")
        try:
            lock_fd = os.open(
                _CANARY_LOCK_NAME,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=root_fd,
            )
        except FileNotFoundError:
            return None
        lock_info = os.fstat(lock_fd)
        lock_name_info = os.stat(
            _CANARY_LOCK_NAME, dir_fd=root_fd, follow_symlinks=False
        )
        if (
            not stat.S_ISREG(lock_info.st_mode)
            or lock_info.st_nlink != 1
            or lock_info.st_uid != os.geteuid()
            or stat.S_IMODE(lock_info.st_mode) != 0o600
            or (lock_info.st_dev, lock_info.st_ino)
            != (lock_name_info.st_dev, lock_name_info.st_ino)
        ):
            raise _error("runtime_lifecycle_qualification_record_invalid")
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise _error("runtime_lifecycle_qualification_record_busy") from exc
        current_root = root.lstat()
        current_lock = os.stat(_CANARY_LOCK_NAME, dir_fd=root_fd, follow_symlinks=False)
        if (current_root.st_dev, current_root.st_ino) != (
            opened_root.st_dev,
            opened_root.st_ino,
        ) or (current_lock.st_dev, current_lock.st_ino) != (
            lock_info.st_dev,
            lock_info.st_ino,
        ):
            raise _error("runtime_lifecycle_qualification_record_invalid")
        try:
            record_fd = os.open(
                _CANARY_QUALIFICATION_NAME,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=root_fd,
            )
        except FileNotFoundError:
            return None
        before = os.fstat(record_fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size <= 0
            or before.st_size > _MAX_CANARY_QUALIFICATION_BYTES
        ):
            raise _error("runtime_lifecycle_qualification_record_invalid")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(record_fd, min(remaining, 8192))
            if not chunk:
                raise _error("runtime_lifecycle_qualification_record_invalid")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(record_fd)
        current_name = os.stat(
            _CANARY_QUALIFICATION_NAME, dir_fd=root_fd, follow_symlinks=False
        )
        if (after.st_dev, after.st_ino, after.st_size) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
        ) or (current_name.st_dev, current_name.st_ino) != (
            before.st_dev,
            before.st_ino,
        ):
            raise _error("runtime_lifecycle_qualification_record_invalid")
        raw = b"".join(chunks)
        value = _d320_parse_json(raw)
        if not isinstance(value, Mapping) or set(value) != {
            "bindings",
            "criteria",
            "issued_at_unix_ns",
            "owner_uid",
            "schema_version",
            "status",
        }:
            raise _error("runtime_lifecycle_qualification_record_invalid")
        criteria = value.get("criteria")
        bindings = value.get("bindings")
        predecessor = (
            bindings.get("predecessor") if isinstance(bindings, Mapping) else None
        )
        profile_sha256 = (
            bindings.get("profile_sha256") if isinstance(bindings, Mapping) else None
        )
        if (
            _d320_canonical_json(dict(value)) != raw
            or value.get("schema_version") != 1
            or value.get("owner_uid") != os.geteuid()
            or type(value.get("issued_at_unix_ns")) is not int
            or value["issued_at_unix_ns"] <= 0
            or value.get("status") not in {"qualified", "unqualified"}
            or not isinstance(criteria, Mapping)
            or set(criteria) != _CANARY_QUALIFICATION_CRITERIA
            or any(
                item not in {"pass", "fail", "unknown"} for item in criteria.values()
            )
            or not isinstance(bindings, Mapping)
            or set(bindings)
            != {
                "candidate_generation",
                "candidate_manifest_digest",
                "client",
                "manager_states_sha256",
                "manager_api_contract",
                "predecessor",
                "profile_sha256",
                "source_commit",
                "source_tree_sha256",
                "target",
            }
            or not isinstance(bindings.get("source_commit"), str)
            or not isinstance(bindings.get("source_tree_sha256"), str)
            or not isinstance(bindings.get("candidate_generation"), str)
            or not isinstance(bindings.get("candidate_manifest_digest"), str)
            or not re.fullmatch(r"[0-9a-f]{40}", bindings["source_commit"])
            or not re.fullmatch(_SHA256_HEX_PATTERN, bindings["source_tree_sha256"])
            or not re.fullmatch(r"[0-9a-f]{40}", bindings["candidate_generation"])
            or not re.fullmatch(
                _ROOT_HOOK_MANIFEST_DIGEST_PATTERN,
                bindings["candidate_manifest_digest"],
            )
            or (
                bindings.get("manager_states_sha256") is not None
                and (
                    not isinstance(bindings.get("manager_states_sha256"), str)
                    or not re.fullmatch(
                        _SHA256_HEX_PATTERN, bindings["manager_states_sha256"]
                    )
                )
            )
            or (
                bindings.get("manager_api_contract") is not None
                and not _valid_manager_api_contract(
                    bindings.get("manager_api_contract")
                )
            )
            or not isinstance(bindings.get("target"), Mapping)
            or set(bindings["target"])
            != {"dev", "gid", "ino", "mode", "realpath", "uid"}
            or not isinstance(bindings["target"].get("realpath"), str)
            or any(
                type(bindings["target"].get(key)) is not int
                for key in ("dev", "gid", "ino", "mode", "uid")
            )
            or (
                bindings.get("client") is not None
                and (
                    not isinstance(bindings.get("client"), Mapping)
                    or set(bindings["client"])
                    != {
                        "artifact_sha256",
                        "compatibility_probe",
                        "features_sha256",
                        "version",
                    }
                    or not isinstance(bindings["client"].get("artifact_sha256"), str)
                    or not re.fullmatch(
                        _SHA256_HEX_PATTERN, bindings["client"]["artifact_sha256"]
                    )
                    or not _valid_client_compatibility_probe(
                        bindings["client"].get("compatibility_probe")
                    )
                    or not isinstance(bindings["client"].get("features_sha256"), str)
                    or not re.fullmatch(
                        _SHA256_HEX_PATTERN, bindings["client"]["features_sha256"]
                    )
                    or not isinstance(bindings["client"].get("version"), str)
                    or not bindings["client"]["version"]
                    or len(bindings["client"]["version"]) > 128
                )
            )
            or (
                value.get("status") == "qualified"
                and (
                    not _valid_manager_api_contract(
                        bindings.get("manager_api_contract")
                    )
                    or bindings.get("manager_states_sha256") is None
                    or profile_sha256 is None
                    or predecessor is None
                    or bindings.get("client") is None
                )
            )
            or (
                profile_sha256 is not None
                and (
                    not isinstance(profile_sha256, str)
                    or not re.fullmatch(_SHA256_HEX_PATTERN, profile_sha256)
                )
            )
            or (
                predecessor is not None
                and (
                    not isinstance(predecessor, Mapping)
                    or set(predecessor)
                    != {"consumer_sha256", "generation", "manifest_digest"}
                    or not isinstance(predecessor.get("consumer_sha256"), str)
                    or not re.fullmatch(
                        _SHA256_HEX_PATTERN, predecessor["consumer_sha256"]
                    )
                    or not isinstance(predecessor.get("generation"), str)
                    or not re.fullmatch(r"[0-9a-f]{40}", predecessor["generation"])
                    or not isinstance(predecessor.get("manifest_digest"), str)
                    or not re.fullmatch(
                        _ROOT_HOOK_MANIFEST_DIGEST_PATTERN,
                        predecessor["manifest_digest"],
                    )
                )
            )
            or (
                criteria.get("client_probe") == "pass"
                and bindings.get("client") is None
            )
            or (
                criteria.get("client_compatibility") == "pass"
                and (
                    not isinstance(bindings.get("client"), Mapping)
                    or not _valid_client_compatibility_probe(
                        bindings["client"].get("compatibility_probe")
                    )
                )
            )
            or (
                value.get("status") == "qualified"
                and (
                    any(
                        criteria[name] != "pass"
                        for name in _CANARY_QUALIFICATION_CRITERIA
                        if name not in {"client_behavior", "manager_actions"}
                    )
                    or criteria["manager_actions"] != "unknown"
                    or criteria["client_behavior"] != "unknown"
                )
            )
        ):
            raise _error("runtime_lifecycle_qualification_record_invalid")
        return value
    except RuntimeLifecycleError:
        raise
    except (OSError, D320CutoverJournalError, ValueError, TypeError) as exc:
        raise _error("runtime_lifecycle_qualification_record_invalid") from exc
    finally:
        if record_fd >= 0:
            os.close(record_fd)
        if lock_fd >= 0:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
        if root_fd >= 0:
            os.close(root_fd)


def _canary_qualification_record(
    *,
    repository: Path,
    home: Path,
    source_commit: str,
    source_tree_digest: str,
    image: _CanaryImage,
    runtime_status: str,
    runtime_features_status: str,
    client_metadata: Mapping[str, object] | None,
    manager_states: Mapping[str, Mapping[str, str]] | None,
    manager_api_contract: Mapping[str, object] | None,
) -> dict[str, object]:
    profile = _regular_bytes(
        repository
        / "src"
        / "the_hive"
        / "markdown"
        / "runtime-release-compatibility-v1.json",
        maximum=64 * 1024,
        mode=0o644,
    )
    profile_qualified = False
    if profile is not None:
        try:
            from the_hive.runtime_layout import (
                validate_runtime_release_compatibility_profile,
            )

            parsed_profile = validate_runtime_release_compatibility_profile(profile)
            profile_qualified = (
                parsed_profile.get("schema_version") == 2
                and parsed_profile.get("status") == "structural_requirements"
            )
        except (ValueError, RuntimeLifecycleError):
            profile_qualified = False
    predecessor = _runtime_identity(home / ".local" / "lib" / "the-hive-runtime")
    client_probe_valid = (
        isinstance(client_metadata, Mapping)
        and isinstance(client_metadata.get("artifact_sha256"), str)
        and re.fullmatch(_SHA256_HEX_PATTERN, client_metadata["artifact_sha256"])
        and isinstance(client_metadata.get("features_sha256"), str)
        and re.fullmatch(_SHA256_HEX_PATTERN, client_metadata["features_sha256"])
        and isinstance(client_metadata.get("version"), str)
        and bool(client_metadata["version"])
        and _valid_client_compatibility_probe(
            client_metadata.get("compatibility_probe")
        )
    )
    criteria = {
        "client_compatibility": (
            "pass" if client_probe_valid and profile_qualified else "unknown"
        ),
        "client_behavior": "unknown",
        "client_probe": ("pass" if client_probe_valid else "unknown"),
        "manager_api_contract": (
            "pass" if _valid_manager_api_contract(manager_api_contract) else "unknown"
        ),
        "manager_actions": "unknown",
        "runtime_canary": runtime_status,
        "runtime_features": runtime_features_status,
    }
    required_bindings_present = (
        isinstance(predecessor, Mapping)
        and all(
            isinstance(predecessor.get(key), str)
            for key in ("consumer_sha256", "generation", "manifest_digest")
        )
        and profile is not None
        and profile_qualified
        and _manager_states_digest(manager_states) is not None
        and _valid_manager_api_contract(manager_api_contract)
        and client_probe_valid
    )
    return {
        "bindings": {
            "candidate_generation": image.generation,
            "candidate_manifest_digest": image.manifest_digest,
            "client": dict(client_metadata) if client_metadata is not None else None,
            "manager_states_sha256": _manager_states_digest(manager_states),
            "manager_api_contract": (
                dict(manager_api_contract) if manager_api_contract is not None else None
            ),
            "predecessor": (
                {
                    "consumer_sha256": predecessor["consumer_sha256"],
                    "generation": predecessor["generation"],
                    "manifest_digest": predecessor["manifest_digest"],
                }
                if isinstance(predecessor, Mapping)
                and all(
                    isinstance(predecessor.get(key), str)
                    for key in ("consumer_sha256", "generation", "manifest_digest")
                )
                else None
            ),
            "profile_sha256": (
                hashlib.sha256(profile).hexdigest() if profile is not None else None
            ),
            "source_commit": source_commit,
            "source_tree_sha256": source_tree_digest,
            "target": _target_binding(home),
        },
        "criteria": criteria,
        "issued_at_unix_ns": time.time_ns(),
        "owner_uid": os.geteuid(),
        "schema_version": 1,
        "status": (
            "qualified"
            if required_bindings_present
            and all(
                value == "pass"
                for name, value in criteria.items()
                if name not in {"client_behavior", "manager_actions"}
            )
            and criteria["manager_actions"] == "unknown"
            and criteria["client_behavior"] == "unknown"
            else "unqualified"
        ),
    }


def _publish_canary_qualification_record(
    *, root: Path, lock_fd: int, value: Mapping[str, object]
) -> None:
    """Atomically publish one owner-produced record while holding Canary EX lock."""

    root_fd = temporary_fd = -1
    temporary_name = f".{_CANARY_QUALIFICATION_NAME}.{secrets.token_hex(12)}.tmp"
    try:
        lock_info = os.fstat(lock_fd)
        root_info = root.lstat()
        root_fd = os.open(
            root,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        opened_root = os.fstat(root_fd)
        current_lock = os.stat(_CANARY_LOCK_NAME, dir_fd=root_fd, follow_symlinks=False)
        if (
            (opened_root.st_dev, opened_root.st_ino)
            != (root_info.st_dev, root_info.st_ino)
            or (current_lock.st_dev, current_lock.st_ino)
            != (lock_info.st_dev, lock_info.st_ino)
            or not stat.S_ISREG(lock_info.st_mode)
            or lock_info.st_uid != os.geteuid()
            or lock_info.st_nlink != 1
            or stat.S_IMODE(lock_info.st_mode) != 0o600
        ):
            raise _error("runtime_lifecycle_qualification_record_invalid")
        raw = _d320_canonical_json(dict(value))
        if len(raw) > _MAX_CANARY_QUALIFICATION_BYTES:
            raise _error("runtime_lifecycle_qualification_record_invalid")
        temporary_fd = os.open(
            temporary_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=root_fd,
        )
        offset = 0
        while offset < len(raw):
            offset += os.write(temporary_fd, raw[offset:])
        os.fsync(temporary_fd)
        temporary_info = os.fstat(temporary_fd)
        try:
            existing = os.stat(
                _CANARY_QUALIFICATION_NAME,
                dir_fd=root_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            existing = None
        if existing is not None and (
            not stat.S_ISREG(existing.st_mode)
            or existing.st_uid != os.geteuid()
            or existing.st_nlink != 1
            or stat.S_IMODE(existing.st_mode) != 0o600
        ):
            raise _error("runtime_lifecycle_qualification_record_invalid")
        latest_root = root.lstat()
        latest_lock = os.stat(_CANARY_LOCK_NAME, dir_fd=root_fd, follow_symlinks=False)
        if (latest_root.st_dev, latest_root.st_ino) != (
            opened_root.st_dev,
            opened_root.st_ino,
        ) or (latest_lock.st_dev, latest_lock.st_ino) != (
            lock_info.st_dev,
            lock_info.st_ino,
        ):
            raise _error("runtime_lifecycle_qualification_record_invalid")
        os.replace(
            temporary_name,
            _CANARY_QUALIFICATION_NAME,
            src_dir_fd=root_fd,
            dst_dir_fd=root_fd,
        )
        published = os.stat(
            _CANARY_QUALIFICATION_NAME,
            dir_fd=root_fd,
            follow_symlinks=False,
        )
        if (published.st_dev, published.st_ino) != (
            temporary_info.st_dev,
            temporary_info.st_ino,
        ):
            raise _error("runtime_lifecycle_qualification_record_invalid")
        os.fsync(root_fd)
    except RuntimeLifecycleError:
        raise
    except (OSError, D320CutoverJournalError) as exc:
        raise _error("runtime_lifecycle_qualification_record_invalid") from exc
    finally:
        if root_fd >= 0:
            if temporary_fd >= 0:
                try:
                    info = os.stat(
                        temporary_name, dir_fd=root_fd, follow_symlinks=False
                    )
                    owned = os.fstat(temporary_fd)
                    if (info.st_dev, info.st_ino) == (owned.st_dev, owned.st_ino):
                        os.unlink(temporary_name, dir_fd=root_fd)
                except FileNotFoundError:
                    pass
            os.close(root_fd)
        if temporary_fd >= 0:
            os.close(temporary_fd)


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
        yield descriptor
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
    manager_states: dict[str, dict[str, str]] | None = None
    qualification_diagnostic: dict[str, object] | None = None
    qualification_input: (
        tuple[_CanaryImage, str, str, Mapping[str, object] | None] | None
    ) = None
    root = _canary_runtime_root()
    try:
        _validate_canary_home(home)
        repository = Path(__file__).resolve().parents[2]
        source_commit, source_tree_digest = _source_tree_binding(repository)
        with _canary_lock(root) as lock_fd:
            qualification_record: dict[str, object] | None = None
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
                payload = _canary_health_payload(image)
                status_code, error_code = _canary_evidence_result(
                    image=image, manager_state=manager_state, payload=payload
                )
                runtime_status = "fail"
                if status_code == "runtime_canary_green":
                    runtime_status = _canary_runtime_qualification_status(
                        image=image, manager_state=manager_state, payload=payload
                    )
                    runtime_features_status = (
                        _canary_runtime_features_qualification_status(
                            image=image, payload=payload
                        )
                    )
                    qualification_input = (
                        image,
                        runtime_status,
                        runtime_features_status,
                        _canary_client_metadata(invocation),
                    )
                if status_code in {"runtime_canary_green", "runtime_canary_red"}:
                    qualification_diagnostic = _canary_qualification_diagnostic(
                        payload=payload,
                        manager_state=manager_state,
                        evidence_status=status_code,
                        runtime_status=runtime_status,
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
            if qualification_diagnostic is not None:
                result["qualification_diagnostic"] = qualification_diagnostic
            if qualification_input is not None:
                (
                    image,
                    runtime_status,
                    runtime_features_status,
                    client_metadata,
                ) = qualification_input
                manager_states = _canary_manager_state_snapshot(systemctl)
                manager_api_contract = _manager_api_contract_snapshot()
                qualification_record = _canary_qualification_record(
                    repository=repository,
                    home=home,
                    source_commit=source_commit,
                    source_tree_digest=source_tree_digest,
                    image=image,
                    runtime_status=runtime_status,
                    runtime_features_status=runtime_features_status,
                    client_metadata=client_metadata,
                    manager_states=manager_states,
                    manager_api_contract=manager_api_contract,
                )
            if qualification_record is not None:
                if _source_tree_binding(repository) != (
                    source_commit,
                    source_tree_digest,
                ):
                    raise _error("runtime_canary_source_changed")
                expected_bindings = qualification_record["bindings"]
                if (
                    _manager_api_contract_snapshot()
                    == expected_bindings.get("manager_api_contract")
                    and _manager_states_digest(
                        _canary_manager_state_snapshot(systemctl)
                    )
                    == expected_bindings.get("manager_states_sha256")
                    and _target_binding(home) == expected_bindings.get("target")
                    and (
                        expected_bindings.get("client") is None
                        or _canonical_codex_client_digest()
                        == expected_bindings["client"].get("artifact_sha256")
                    )
                ):
                    _publish_canary_qualification_record(
                        root=root, lock_fd=lock_fd, value=qualification_record
                    )
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
        lease = _LifecycleLockLease(
            home=home.resolve(strict=True),
            lock_path=lock,
            descriptor=descriptor,
            identity=(info.st_dev, info.st_ino),
            owner_pid=os.getpid(),
        )
        yield lease
    except RuntimeLifecycleError:
        raise
    except OSError as exc:
        raise _error("runtime_lifecycle_lock_invalid") from exc
    finally:
        if "lease" in locals():
            lease.active = False
        if descriptor >= 0:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)


def _execute_cutover(
    *, home: Path, systemctl: Systemctl = _systemctl_default
) -> dict[str, object]:
    """Reject the retired transaction body before any pin or manager effect."""

    _ = home, systemctl
    return {
        "status": "runtime_lifecycle_v2_journal_unavailable",
        "raw_output": "not_returned",
    }


def cutover(
    *,
    home: Path,
    plan_sha256: str | None = None,
    phase: str | None = None,
    systemctl: Systemctl | None = None,
) -> dict[str, object]:
    """Consume only a fresh public plan before entering any transaction body."""

    if plan_sha256 is None:
        return {
            "status": "runtime_lifecycle_plan_required",
            "raw_output": "not_returned",
        }
    if re.fullmatch(_SHA256_HEX_PATTERN, plan_sha256) is None:
        return {
            "status": "runtime_lifecycle_plan_digest_invalid",
            "raw_output": "not_returned",
        }
    selected_systemctl = systemctl or _systemctl_default
    if phase == "recover":
        try:
            journal = _v2_load_journal(home)
            if journal is None:
                return {
                    "status": "runtime_lifecycle_journal_missing",
                    "raw_output": "not_returned",
                }
            if journal.payload["plan_sha256"] != plan_sha256:
                return {
                    "status": "runtime_lifecycle_plan_changed",
                    "raw_output": "not_returned",
                }
            return _v2_recover_phase(
                home=home, plan_sha256=plan_sha256, systemctl=selected_systemctl
            )
        except RuntimeLifecycleError as exc:
            return {"status": str(exc), "raw_output": "not_returned"}
    current = plan(home=home, systemctl=selected_systemctl)
    if current.get("plan_sha256") != plan_sha256:
        return {
            "status": "runtime_lifecycle_plan_changed",
            "raw_output": "not_returned",
        }
    if phase not in {"install", "activate", "observe", "commit", "recover"}:
        return {
            "status": "runtime_lifecycle_phase_required",
            "raw_output": "not_returned",
        }
    if current.get("status") != "runtime_lifecycle_plan_ready":
        return {
            "status": "runtime_lifecycle_plan_blocked",
            "reason_codes": current.get("reason_codes", []),
            "raw_output": "not_returned",
        }
    try:
        if phase == "install":
            return _v2_install_phase(
                home=home,
                plan_result=current,
                systemctl=selected_systemctl,
            )
        if phase == "activate":
            return _v2_activate_phase(
                home=home,
                plan_sha256=plan_sha256,
                systemctl=selected_systemctl,
            )
        if phase == "observe":
            return _v2_observe_phase(
                home=home,
                plan_sha256=plan_sha256,
                systemctl=selected_systemctl,
            )
        if phase == "commit":
            return _v2_commit_phase(
                home=home,
                plan_sha256=plan_sha256,
                systemctl=selected_systemctl,
            )
        return {
            "status": "runtime_lifecycle_phase_unavailable",
            "raw_output": "not_returned",
        }
    except RuntimeLifecycleError as exc:
        return {"status": str(exc), "raw_output": "not_returned"}


def _verify_candidate_compatibility_profile_stage(
    layout: object, expected_sha256: str
) -> None:
    """Require the sealed candidate member to match the immutable plan bytes."""

    try:
        _d320_sha256(expected_sha256)
        raw = layout.read_attested_file(
            "src/the_hive/markdown/runtime-release-compatibility-v1.json"
        )
    except (AttributeError, OSError, ValueError, RuntimeLifecycleError) as exc:
        raise _error("runtime_lifecycle_compatibility_profile_changed") from exc
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise _error("runtime_lifecycle_compatibility_profile_changed")


def main() -> int:
    parser = argparse.ArgumentParser(prog="the-hive-runtime-service")
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("canary", "cutover", "plan", "status", "verify"):
        child = commands.add_parser(command)
        child.add_argument("--home", type=Path, required=True)
        if command == "cutover":
            child.add_argument("--plan-sha256")
            child.add_argument(
                "--phase",
                choices=("install", "activate", "observe", "commit", "recover"),
            )
    arguments = parser.parse_args()
    if arguments.command == "cutover":
        result = cutover(
            home=arguments.home,
            plan_sha256=arguments.plan_sha256,
            phase=arguments.phase,
        )
    else:
        operation = {
            "canary": canary,
            "plan": plan,
            "status": status,
            "verify": verify,
        }[arguments.command]
        result = operation(home=arguments.home)
    print(json.dumps(result, sort_keys=True))
    status_value = result.get("status")
    if arguments.command == "plan":
        return (
            0
            if status_value
            in {"runtime_lifecycle_plan_blocked", "runtime_lifecycle_plan_ready"}
            else 1
        )
    return (
        0
        if status_value
        in {
            "runtime_canary_green",
            "runtime_lifecycle_green",
            "runtime_lifecycle_install_complete",
            "runtime_lifecycle_activation_complete",
            "runtime_lifecycle_observation_complete",
            "runtime_lifecycle_commit_complete",
            "runtime_lifecycle_recovery_complete",
            "runtime_lifecycle_recovery_not_needed",
        }
        else 1
    )


__all__ = ["canary", "cutover", "main", "status", "verify"]
