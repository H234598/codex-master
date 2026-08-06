import argparse

import pytest

from codex_master.hive.cli import add_hive_cli_parsers, run_hive_cli
from codex_master.hive.migration import compare_legacy_and_hive_assignment, rollback_hive_state
from codex_master.hive.tools import call_hive_tool, hive_tool_definitions


def test_read_only_hive_tools_have_closed_schemas_and_bounded_output() -> None:
    definitions = hive_tool_definitions()
    assert len(definitions) == 12
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
    assert run_hive_cli(args)["healthy"] is True
    assert compare_legacy_and_hive_assignment({})["comparable"] is False
    assert rollback_hive_state(dry_run=True)["statefiles_deleted"] is False
