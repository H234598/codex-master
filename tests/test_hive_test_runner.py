from __future__ import annotations

from pathlib import Path

import pytest

from codex_master.hive.indexed_test_inventory import PythonTestIndexBuilder
from codex_master.hive.javascript_test_inventory import JavaScriptTestIndexBuilder
from codex_master.hive.evidence_runner import TestEvidenceRunner as EvidenceRunner
from codex_master.hive.evidence_store import TestStatusStore as StatusStore

from test_hive_test_evidence import DIGEST_A, DIGEST_B


def project(root: Path, body: str, *, timeout: int = 10):
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
        test_metadata={test_id: {"timeout_seconds": timeout}},
    )
    return index, test_id


def runner(root: Path, store: StatusStore) -> EvidenceRunner:
    return EvidenceRunner(
        root,
        store,
        executor_fingerprint=DIGEST_A,
        boot_id_digest=DIGEST_B,
        environment_digest=DIGEST_A,
    )


def test_runner_mints_passed_receipt_only_after_real_pytest_exit(tmp_path: Path) -> None:
    index, test_id = project(tmp_path, "    assert run() == 1\n")
    store = StatusStore(tmp_path / ".state")

    result = runner(tmp_path, store).run(index, test_id, expected_index_digest=index.digest)

    assert result.result == "passed"
    assert result.reason_code == "test.run_passed"
    assert store.latest("example", DIGEST_A, test_id) == result
    assert "stdout" not in result.public()


def test_runner_records_failed_exit_without_reuse_ttl(tmp_path: Path) -> None:
    index, test_id = project(tmp_path, "    assert run() == 2\n")
    store = StatusStore(tmp_path / ".state")

    result = runner(tmp_path, store).run(index, test_id, expected_index_digest=index.digest)

    assert (result.result, result.reason_code) == ("failed", "test.run_failed")
    assert result.expires_monotonic_ns == result.finished_monotonic_ns


def test_runner_times_out_own_process_group_and_records_blocked(tmp_path: Path) -> None:
    index, test_id = project(
        tmp_path,
        "    import time\n    time.sleep(2)\n    assert run() == 1\n",
        timeout=1,
    )
    store = StatusStore(tmp_path / ".state")

    result = runner(tmp_path, store).run(index, test_id, expected_index_digest=index.digest)

    assert (result.result, result.reason_code) == ("blocked", "test.run_timeout")


def test_runner_rejects_unknown_test_without_starting_process(tmp_path: Path) -> None:
    index, _ = project(tmp_path, "    assert run() == 1\n")
    store = StatusStore(tmp_path / ".state")

    with pytest.raises(ValueError, match="test.test_uncollectable"):
        runner(tmp_path, store).run(
            index,
            "pytest:tests/test_example.py:test_missing",
            expected_index_digest=index.digest,
        )


def test_runner_executes_one_exact_indexed_node_test(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "src/example.mjs").write_text(
        "export function add(left, right) { return left + right; }\n",
        encoding="utf-8",
    )
    (tmp_path / "tests/test-example.mjs").write_text(
        'import assert from "node:assert/strict";\n'
        'import test from "node:test";\n'
        'import { add } from "../src/example.mjs";\n'
        'test("add contract", () => { assert.equal(add(1, 2), 3); });\n',
        encoding="utf-8",
    )
    function_id = "javascript:src/example.mjs:add"
    test_id = "node_test:tests/test-example.mjs:add contract"
    index = JavaScriptTestIndexBuilder(tmp_path).build(
        repository_id="example",
        generation=1,
        source_paths=("src/example.mjs",),
        test_paths=("tests/test-example.mjs",),
        bindings={function_id: (test_id,)},
    )
    store = StatusStore(tmp_path / ".state")

    result = runner(tmp_path, store).run(index, test_id, expected_index_digest=index.digest)

    assert (result.result, result.reason_code) == ("passed", "test.run_passed")
