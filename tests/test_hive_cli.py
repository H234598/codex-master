import argparse

from codex_master.hive.cli import add_hive_cli_parsers, run_hive_cli


ANCHOR_KEY = "sha256:" + "a" * 64


def parser():
    root = argparse.ArgumentParser()
    add_hive_cli_parsers(root.add_subparsers(dest="command"))
    return root


def test_reset_anchor_cli_dry_run_is_bounded_and_execute_is_gated() -> None:
    dry_run_args = parser().parse_args(["reset-anchor-run", "--dry-run", "--anchor-key", ANCHOR_KEY])
    dry_run = run_hive_cli(dry_run_args)
    assert dry_run["mode"] == "dry_run"
    assert dry_run["mutation_performed"] is False
    assert dry_run["reason_code"] == "anchor_due"

    execute_args = parser().parse_args(["reset-anchor-run", "--execute", "--anchor-key", ANCHOR_KEY])
    executed = run_hive_cli(execute_args)
    assert executed["allowed"] is False
    assert executed["reason_code"] == "selection_proactive_anchor_safety_gate"
    assert executed["mutation_performed"] is False


def test_migration_cli_is_read_only_and_requires_explicit_dry_run() -> None:
    status = run_hive_cli(parser().parse_args(["hive", "migration-status"]))
    assert status["mode"] == "shadow"
    assert status["mutation_performed"] is False

    rollback = run_hive_cli(parser().parse_args(["hive", "rollback", "--dry-run"]))
    assert rollback["dry_run"] is True
    assert rollback["rollback_allowed"] is False
    assert rollback["statefiles_deleted"] is False
