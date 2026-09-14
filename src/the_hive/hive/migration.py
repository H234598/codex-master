"""Reversible, read-only legacy/Hive migration diagnostics."""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json


def migration_status(*, mode: str = "shadow") -> Mapping[str, object]:
    if mode not in {"disabled", "shadow", "enforced"}:
        raise ValueError("invalid_migration_mode")
    return {"mode": mode, "legacy": "available", "hive": "shadow_only", "mutation_performed": False, "raw_output": "not_returned"}


def enable_shadow_mode() -> Mapping[str, object]:
    return {"mode": "shadow", "mutation_performed": False, "requires_restart": False, "raw_output": "not_returned"}


def compare_legacy_and_hive_assignment(record: Mapping[str, object]) -> Mapping[str, object]:
    if not isinstance(record, Mapping):
        raise ValueError("invalid_migration_record")
    legacy = record.get("legacy")
    hive = record.get("hive")
    if not isinstance(legacy, Mapping) or not isinstance(hive, Mapping):
        return {"comparable": False, "reason_code": "missing_comparison_side", "mutation_performed": False, "raw_output": "not_returned"}
    left = hashlib.sha256(json.dumps(dict(legacy), sort_keys=True, ensure_ascii=True).encode()).hexdigest()
    right = hashlib.sha256(json.dumps(dict(hive), sort_keys=True, ensure_ascii=True).encode()).hexdigest()
    return {"comparable": True, "equal": left == right, "legacy_digest": f"sha256:{left}", "hive_digest": f"sha256:{right}", "mutation_performed": False, "raw_output": "not_returned"}


def reconcile_runtime_state() -> Mapping[str, object]:
    return {"reconciled": False, "reason_code": "runtime_context_required", "mutation_performed": False, "raw_output": "not_returned"}


def rollback_hive_state(*, dry_run: bool) -> Mapping[str, object]:
    if not isinstance(dry_run, bool):
        raise ValueError("dry_run_required")
    return {"dry_run": dry_run, "rollback_allowed": False, "statefiles_deleted": False, "pool_changed": False, "raw_output": "not_returned"}


__all__ = ["compare_legacy_and_hive_assignment", "enable_shadow_mode", "migration_status", "reconcile_runtime_state", "rollback_hive_state"]
