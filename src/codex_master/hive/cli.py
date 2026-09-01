"""Small read-only/Dry-run CLI adapter for Hive diagnostics."""

from __future__ import annotations

import argparse
from collections.abc import Mapping
from datetime import datetime, timezone
import time
from typing import TYPE_CHECKING

from codex_master.hive.migration import migration_status, rollback_hive_state
from codex_master.hive.runtime import HiveRuntimeEvidence
from codex_master.hive.status import hive_doctor, hive_status, selection_status
from codex_master.runtime_status import runtime_status
from codex_master.selection.reset_anchor import AnchorRecord, ResetAnchorPlanner

if TYPE_CHECKING:
    from codex_master.hive.evidence_service import HiveTestEvidenceService


def add_hive_cli_parsers(subparsers: object, *, fleet_subparsers: object | None = None) -> None:
    if not hasattr(subparsers, "add_parser"):
        raise ValueError("invalid_cli_parser")
    hive = subparsers.add_parser("hive", help="Validate or inspect Hive; DP and SP scheduling remain separate")
    hive_sub = hive.add_subparsers(dest="hive_command", required=True)
    for name in ("validate", "status", "doctor", "migration-status", "runtime-status"):
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
    if fleet_subparsers is not None:
        if not hasattr(fleet_subparsers, "add_parser"):
            raise ValueError("invalid_cli_parser")
        test = fleet_subparsers.add_parser("test", help="Plan, run, or inspect canonical Hive tests")
        test_sub = test.add_subparsers(dest="hive_test_namespace", required=True)
        index = test_sub.add_parser("index")
        index_sub = index.add_subparsers(dest="hive_test_command", required=True)
        index_sub.add_parser("validate")
        index_sub.add_parser("status")
        plan = test_sub.add_parser("plan")
        plan.set_defaults(hive_test_command="plan")
        plan.add_argument("--changed-path", action="append", default=[])
        plan.add_argument("--function-id", action="append", default=[])
        plan.add_argument("--phase", choices=["change", "branch", "merge", "release"], default="change")
        plan.add_argument("--base-revision", default="working-tree")
        plan.add_argument("--target-revision", default="working-tree")
        run = test_sub.add_parser("run")
        run.set_defaults(hive_test_command="run")
        run.add_argument("test_id")
        run.add_argument("--index-digest", required=True)
        status = test_sub.add_parser("status")
        status.set_defaults(hive_test_command="status")
        invalidate = test_sub.add_parser("invalidate")
        invalidate.set_defaults(hive_test_command="invalidate")
        invalidate.add_argument("evidence_id")
        invalidate.add_argument("--index-digest", required=True)


def run_hive_cli(
    args: object,
    *,
    runtime_evidence: HiveRuntimeEvidence | None = None,
    test_service: HiveTestEvidenceService | None = None,
) -> Mapping[str, object]:
    if isinstance(args, argparse.Namespace):
        command = getattr(args, "hive_command", None)
    elif isinstance(args, Mapping):
        command = args.get("hive_command")
    else:
        raise ValueError("invalid_cli_args")
    test_command = (
        getattr(args, "hive_test_command", None)
        if isinstance(args, argparse.Namespace)
        else args.get("hive_test_command")
    )
    if test_command is not None:
        from codex_master.hive.evidence_service import build_local_test_service, probe_test_index

        if test_command in {"validate", "status"} and getattr(args, "hive_test_namespace", None) == "index":
            return test_service.index_status() if test_service is not None else probe_test_index()
        service = test_service or build_local_test_service()
        if test_command == "plan":
            request = service.request(
                changed_paths=tuple(args.changed_path),
                function_ids=tuple(args.function_id),
                requested_phase=args.phase,
                base_revision=args.base_revision,
                target_revision=args.target_revision,
            )
            return service.plan(request, now_monotonic_ns=time.monotonic_ns()).public()
        if test_command == "run":
            receipt = service.run(args.test_id, expected_index_digest=args.index_digest)
            return {"evidence_id": receipt.evidence_id, "receipt": receipt.public()}
        if test_command == "status":
            request = service.request()
            return service.status(request, now_monotonic_ns=time.monotonic_ns())
        if test_command == "invalidate":
            service.invalidate(args.evidence_id, expected_index_digest=args.index_digest)
            return {"invalidated": True, "evidence_id": args.evidence_id}
        raise ValueError("unknown_hive_test_command")
    if command in {"validate", "status"}:
        return hive_status(runtime_evidence=runtime_evidence)
    if command == "doctor":
        return hive_doctor(runtime_evidence=runtime_evidence)
    if command == "migration-status":
        return migration_status()
    if command == "runtime-status":
        return runtime_status()
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
