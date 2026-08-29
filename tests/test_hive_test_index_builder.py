from __future__ import annotations

from pathlib import Path

import pytest

from codex_master.hive.test_index import TestIndexError as IndexError
from codex_master.hive.test_index_builder import PythonTestIndexBuilder


def write_project(root: Path, *, asserted: bool = True) -> dict[str, tuple[str, ...]]:
    (root / "src").mkdir()
    (root / "tests").mkdir()
    (root / "src/example.py").write_text(
        "def _normalize(value: str) -> str:\n"
        "    return value.strip()\n\n"
        "class Example:\n"
        "    def run(self, value: str = 'ok') -> str:\n"
        "        return _normalize(value)\n",
        encoding="utf-8",
    )
    assertion = "    assert _normalize(' x ') == 'x'\n" if asserted else "    _normalize(' x ')\n"
    (root / "tests/test_example.py").write_text(
        "from example import Example, _normalize\n\n"
        "def test_normalize():\n"
        f"{assertion}\n"
        "def test_example_run():\n"
        "    assert Example().run() == 'ok'\n",
        encoding="utf-8",
    )
    return {
        "python:src/example.py:_normalize": (
            "pytest:tests/test_example.py:test_normalize",
        ),
        "python:src/example.py:Example.run": (
            "pytest:tests/test_example.py:test_example_run",
        ),
    }


def test_builder_inventories_private_functions_tests_and_assertions(tmp_path: Path) -> None:
    bindings = write_project(tmp_path)

    index = PythonTestIndexBuilder(tmp_path).build(
        repository_id="example",
        generation=1,
        source_paths=("src/example.py",),
        test_paths=("tests/test_example.py",),
        bindings=bindings,
    )

    assert [item.function_id for item in index.functions] == sorted(bindings)
    assert [item.test_id for item in index.tests] == sorted(
        test_id for test_ids in bindings.values() for test_id in test_ids
    )
    assert all(item.assertion_digest.startswith("sha256:") for item in index.tests)


def test_builder_fails_closed_for_unindexed_function(tmp_path: Path) -> None:
    bindings = write_project(tmp_path)
    bindings.pop("python:src/example.py:_normalize")

    with pytest.raises(IndexError, match="test.function_unindexed"):
        PythonTestIndexBuilder(tmp_path).build(
            repository_id="example",
            generation=1,
            source_paths=("src/example.py",),
            test_paths=("tests/test_example.py",),
            bindings=bindings,
        )


def test_builder_fails_closed_when_bound_test_has_no_assertion(tmp_path: Path) -> None:
    bindings = write_project(tmp_path, asserted=False)

    with pytest.raises(IndexError, match="test.assertion_missing"):
        PythonTestIndexBuilder(tmp_path).build(
            repository_id="example",
            generation=1,
            source_paths=("src/example.py",),
            test_paths=("tests/test_example.py",),
            bindings=bindings,
        )


def test_builder_digest_changes_with_function_semantics(tmp_path: Path) -> None:
    bindings = write_project(tmp_path)
    builder = PythonTestIndexBuilder(tmp_path)
    before = builder.build(
        repository_id="example",
        generation=1,
        source_paths=("src/example.py",),
        test_paths=("tests/test_example.py",),
        bindings=bindings,
    )
    source = tmp_path / "src/example.py"
    source.write_text(source.read_text().replace("value.strip()", "value.rstrip()"))
    after = builder.build(
        repository_id="example",
        generation=2,
        source_paths=("src/example.py",),
        test_paths=("tests/test_example.py",),
        bindings=bindings,
    )

    assert before.source_root_digest != after.source_root_digest
    assert before.functions[1].source_digest != after.functions[1].source_digest
