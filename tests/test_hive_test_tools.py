from __future__ import annotations
from pathlib import Path

import pytest

from the_hive.hive.evidence_runner import TestEvidenceRunner as EvidenceRunner
from the_hive.hive.evidence_service import HiveTestEvidenceService, build_local_test_service
from the_hive.hive.evidence_store import TestStatusStore as StatusStore
from the_hive.hive.indexed_test_inventory import PythonTestIndexBuilder
from the_hive.hive.tools import call_hive_tool, hive_tool_definitions

from test_hive_test_evidence import DIGEST_A, DIGEST_B


def project(root: Path, body: str):
    (root / "src").mkdir()
    (root / "tests").mkdir()
    (root / "src/example.py").write_text("def run():\n    return 1\n", encoding="utf-8")
    (root / "tests/test_example.py").write_text(
        "from example import run\n\n"
        "def test_run():\n"
        f"{body}",
        encoding="utf-8",
    )
    function_id = "python:src/example.py:run"
    test_id = "pytest:tests/test_example.py:test_run"
    index = PythonTestIndexBuilder(root).build(
        repository_id="example",
        generation=1,
        source_paths=("src/example.py",),
        test_paths=("tests/test_example.py",),
        bindings={function_id: (test_id,)},
    )
    return index, test_id


def service(root: Path, body: str):
    index, test_id = project(root, body)
    store = StatusStore(root / ".state")
    runner = EvidenceRunner(
        root,
        store,
        executor_fingerprint=DIGEST_A,
        boot_id_digest=DIGEST_B,
        environment_digest=DIGEST_A,
    )
    return HiveTestEvidenceService(index, store, runner), test_id


def test_mcp_test_tools_share_service_contract_and_closed_schemas(tmp_path: Path) -> None:
    evidence_service, test_id = service(tmp_path, "    assert run() == 1\n")
    names = {item["name"] for item in hive_tool_definitions()}

    status = call_hive_tool("hive_test_index_status", test_service=evidence_service)
    plan = call_hive_tool(
        "hive_test_plan",
        {"changed_paths": ["src/example.py"]},
        test_service=evidence_service,
    )
    run = call_hive_tool(
        "hive_test_run",
        {"test_id": test_id, "index_digest": status["index_digest"]},
        test_service=evidence_service,
    )
    projected = call_hive_tool("hive_test_status", test_service=evidence_service)
    invalidated = call_hive_tool(
        "hive_test_invalidate",
        {
            "evidence_id": run["evidence_id"],
            "index_digest": status["index_digest"],
        },
        test_service=evidence_service,
    )

    assert {"hive_test_index_status", "hive_test_plan", "hive_test_run", "hive_test_status", "hive_test_invalidate"} <= names
    assert plan["tests"][0]["action"] == "run"
    assert run["receipt"]["result"] == "passed"
    assert projected["counts"]["passed"] == 1
    assert invalidated["invalidated"] is True


def test_local_service_does_not_read_a_retired_product_index(tmp_path: Path) -> None:
    index, _ = project(tmp_path, "    assert run() == 1\n")
    index_path = tmp_path / ".hive" / "test-index.v1.json"
    index_path.parent.mkdir()
    index_path.write_bytes(index.canonical_bytes())

    with pytest.raises(ValueError, match="test.index_missing"):
        build_local_test_service(tmp_path, tmp_path / ".state")


def test_test_tool_rejects_absolute_changed_path(tmp_path: Path) -> None:
    evidence_service, _ = service(tmp_path, "    assert run() == 1\n")

    with pytest.raises(ValueError, match="test.index_invalid"):
        call_hive_tool(
            "hive_test_plan",
            {"changed_paths": ["/secret/path"]},
            test_service=evidence_service,
        )
