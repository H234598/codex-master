import argparse

import pytest

from codex_master.hive.cli import add_hive_cli_parsers, run_hive_cli
from codex_master.hive.migration import compare_legacy_and_hive_assignment, rollback_hive_state
from codex_master.hive.tools import call_hive_tool, hive_tool_definitions
from codex_master.hive.runtime import HiveRuntimeEvidence


def test_read_only_hive_tools_have_closed_schemas_and_bounded_output() -> None:
    definitions = hive_tool_definitions()
    assert len(definitions) == 17
    assert all(item["inputSchema"]["additionalProperties"] is False for item in definitions)
    assert not {"execute_global_request", "retry_repo_dispatch", "cancel_global_request"} & {
        item["name"] for item in definitions
    }
    assert call_hive_tool("hive_status")["raw_output"] == "not_returned"
    with pytest.raises(ValueError, match="hive_tool_arguments_not_allowed"):
        call_hive_tool("hive_status", {"write": True})


def test_cli_is_read_only_and_migration_requires_both_comparison_sides() -> None:
    parser = argparse.ArgumentParser()
    add_hive_cli_parsers(parser.add_subparsers(dest="command"))
    args = parser.parse_args(["hive", "doctor"])
    assert run_hive_cli(args)["healthy"] is False
    assert compare_legacy_and_hive_assignment({})["comparable"] is False
    assert rollback_hive_state(dry_run=True)["statefiles_deleted"] is False


def test_mcp_status_projects_the_supplied_canonical_runtime_evidence() -> None:
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
    status = call_hive_tool("hive_status", runtime_evidence=evidence)
    assert status["mode"] == "shadow"
    assert status["authority"] == "fail_closed"
    assert status["checks"]["state"] == "not_configured"
    assert status["mutation_performed"] is False
