"""Small read-only/Dry-run CLI adapter for Hive diagnostics."""

from __future__ import annotations

import argparse
from collections.abc import Mapping
from datetime import datetime, timezone

from codex_master.hive.migration import migration_status, rollback_hive_state
from codex_master.hive.runtime import HiveRuntimeEvidence
from codex_master.hive.status import hive_doctor, hive_status, selection_status
from codex_master.selection.reset_anchor import AnchorRecord, ResetAnchorPlanner


def add_hive_cli_parsers(subparsers: object) -> None:
    if not hasattr(subparsers, "add_parser"):
        raise ValueError("invalid_cli_parser")
    hive = subparsers.add_parser("hive", help="Validate or inspect Hive; DP and SP scheduling remain separate")
    hive_sub = hive.add_subparsers(dest="hive_command", required=True)
    for name in ("validate", "status", "doctor", "migration-status"):
        hive_sub.add_parser(name)
    rollback = hive_sub.add_parser("rollback", help="Show the reversible rollback contract without mutating state")
    rollback.add_argument("--dry-run", action="store_true", required=True)
    selection = subparsers.add_parser("selection-status", help="Show read-only Selection status")
    selection.set_defaults(hive_command="selection-status")
    reset_anchor = subparsers.add_parser("reset-anchor-run", help="Plan a passive reset anchor without execution")
    reset_mode = reset_anchor.add_mutually_exclusive_group(required=True)
    reset_mode.add_argument("--dry-run", action="store_true")
    reset_mode.add_argument("--execute", action="store_true")
    reset_anchor.add_argument("--anchor-key", required=True)
    reset_anchor.set_defaults(hive_command="reset-anchor-run")


def run_hive_cli(
    args: object,
    *,
    runtime_evidence: HiveRuntimeEvidence | None = None,
) -> Mapping[str, object]:
    if isinstance(args, argparse.Namespace):
        command = getattr(args, "hive_command", None)
    elif isinstance(args, Mapping):
        command = args.get("hive_command")
    else:
        raise ValueError("invalid_cli_args")
    if command in {"validate", "status"}:
        return hive_status(runtime_evidence=runtime_evidence)
    if command == "doctor":
        return hive_doctor(runtime_evidence=runtime_evidence)
    if command == "migration-status":
        return migration_status()
    if command == "rollback":
        dry_run = args.dry_run if isinstance(args, argparse.Namespace) else args.get("dry_run")
        return rollback_hive_state(dry_run=dry_run)
    if command == "selection-status":
        return selection_status()
    if command == "reset-anchor-run":
        anchor_key = args.anchor_key if isinstance(args, argparse.Namespace) else args.get("anchor_key")
        record = AnchorRecord(anchor_key, "due", 0, None, None, datetime.now(timezone.utc))
        planner = ResetAnchorPlanner(record, allowed_anchor_keys=(anchor_key,))
        now = datetime.now(timezone.utc)
        if bool(getattr(args, "dry_run", False) if isinstance(args, argparse.Namespace) else args.get("dry_run", False)):
            return planner.dry_run(now=now)
        plan = planner.plan_due(now=now)
        if plan is None:
            return planner.dry_run(now=now)
        return planner.execute(plan)
    raise ValueError("unknown_hive_command")


__all__ = ["add_hive_cli_parsers", "run_hive_cli"]
