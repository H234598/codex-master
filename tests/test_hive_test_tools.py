from __future__ import annotations

from pathlib import Path

import pytest

from codex_master.hive.evidence_service import build_local_test_service, load_test_index
from codex_master.hive.tools import call_hive_tool, hive_tool_definitions

from test_hive_test_runner import project


def test_mcp_test_tools_share_service_contract_and_closed_schemas(tmp_path: Path) -> None:
    index, test_id = project(tmp_path, "    assert run() == 1\n")
    (tmp_path / ".hive").mkdir()
    (tmp_path / ".hive/test-index.v1.json").write_bytes(index.canonical_bytes())
    service = build_local_test_service(tmp_path, tmp_path / ".state")
    names = {item["name"] for item in hive_tool_definitions()}

    status = call_hive_tool("hive_test_index_status", test_service=service)
    plan = call_hive_tool(
        "hive_test_plan",
        {"changed_paths": ["src/example.py"]},
        test_service=service,
    )
    run = call_hive_tool(
        "hive_test_run",
        {"test_id": test_id, "index_digest": status["index_digest"]},
        test_service=service,
    )
    projected = call_hive_tool("hive_test_status", test_service=service)
    invalidated = call_hive_tool(
        "hive_test_invalidate",
        {
            "evidence_id": run["evidence_id"],
            "index_digest": status["index_digest"],
        },
        test_service=service,
    )

    assert {"hive_test_index_status", "hive_test_plan", "hive_test_run", "hive_test_status", "hive_test_invalidate"} <= names
    assert plan["tests"][0]["action"] == "run"
    assert run["receipt"]["result"] == "passed"
    assert projected["counts"]["passed"] == 1
    assert invalidated["invalidated"] is True


def test_index_loader_fails_closed_for_missing_index(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="test.index_missing"):
        load_test_index(tmp_path)


def test_test_tool_rejects_absolute_changed_path(tmp_path: Path) -> None:
    index, _ = project(tmp_path, "    assert run() == 1\n")
    (tmp_path / ".hive").mkdir()
    (tmp_path / ".hive/test-index.v1.json").write_bytes(index.canonical_bytes())
    service = build_local_test_service(tmp_path, tmp_path / ".state")

    with pytest.raises(ValueError, match="test.index_invalid"):
        call_hive_tool(
            "hive_test_plan",
            {"changed_paths": ["/secret/path"]},
            test_service=service,
        )
