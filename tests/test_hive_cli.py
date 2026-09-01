import argparse

from codex_master.hive.cli import add_hive_cli_parsers, run_hive_cli
from codex_master.hive.runtime import HiveRuntimeEvidence


ANCHOR_KEY = "sha256:" + "a" * 64


def parser():
    root = argparse.ArgumentParser()
    sub = root.add_subparsers(dest="command")
    fleet = sub.add_parser("fleet")
    fleet_sub = fleet.add_subparsers(dest="fleet_namespace", required=True)
    add_hive_cli_parsers(sub, fleet_subparsers=fleet_sub)
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


def test_cli_status_and_doctor_accept_the_same_canonical_runtime_evidence() -> None:
    evidence = HiveRuntimeEvidence(
        schema_version=1,
        mode="shadow",
        config_digest="sha256:" + "a" * 64,
        catalog_digest="sha256:" + "b" * 64,
        repository="not_configured",
        principal="not_configured",
        authority="fail_closed",
        state="not_configured",
        pilot="blocked",
        reason_codes=("repository_not_configured", "principal_not_configured", "state_not_configured"),
        mutation_performed=False,
    )
    status = run_hive_cli({"hive_command": "status"}, runtime_evidence=evidence)
    doctor = run_hive_cli({"hive_command": "doctor"}, runtime_evidence=evidence)
    assert status["checks"] == doctor["checks"]
    assert status["mode"] == doctor["mode"] == "shadow"
    assert status["mutation_performed"] is False
    assert doctor["mutation_performed"] is False


def test_runtime_status_is_a_dedicated_hive_cli_command() -> None:
    try:
        args = parser().parse_args(["hive", "runtime-status"])
    except SystemExit:
        command = None
    else:
        command = args.hive_command

    assert command == "runtime-status"


def test_runtime_status_returns_only_the_autonomous_contract() -> None:
    try:
        result = run_hive_cli({"hive_command": "runtime-status"})
    except ValueError:
        result = {}

    assert set(result) == {"ok", "metadata", "mcp_surface", "raw_output"}


def test_fleet_test_cli_uses_injected_shared_service(tmp_path) -> None:
    from test_hive_test_service import service

    evidence_service, test_id = service(tmp_path)
    index_status = run_hive_cli(
        parser().parse_args(["fleet", "test", "index", "validate"]),
        test_service=evidence_service,
    )
    plan = run_hive_cli(
        parser().parse_args(["fleet", "test", "plan", "--changed-path", "src/example.py"]),
        test_service=evidence_service,
    )
    run = run_hive_cli(
        parser().parse_args(
            ["fleet", "test", "run", test_id, "--index-digest", index_status["index_digest"]]
        ),
        test_service=evidence_service,
    )

    assert plan["tests"][0]["action"] == "run"
    assert run["receipt"]["result"] == "passed"
