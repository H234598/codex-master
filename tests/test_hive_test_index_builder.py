from __future__ import annotations

from pathlib import Path

import pytest

from codex_master.hive.indexed_tests import TestIndexError as IndexError
from codex_master.hive.indexed_test_inventory import PythonTestIndexBuilder


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


def test_builder_ignores_unbound_tests_in_selected_test_files(tmp_path: Path) -> None:
    bindings = write_project(tmp_path)
    test_path = tmp_path / "tests/test_example.py"
    test_path.write_text(
        test_path.read_text(encoding="utf-8")
        + "\ndef test_unrelated_repository_check():\n"
        + "    assert True\n",
        encoding="utf-8",
    )

    index = PythonTestIndexBuilder(tmp_path).build(
        repository_id="example",
        generation=1,
        source_paths=("src/example.py",),
        test_paths=("tests/test_example.py",),
        bindings=bindings,
    )

    assert [item.test_id for item in index.tests] == sorted(
        test_id for test_ids in bindings.values() for test_id in test_ids
    )


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


def test_builder_excludes_protocol_declarations_and_indexes_async_class_tests(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "src/example.py").write_text(
        "from typing import Protocol\n\n"
        "class Port(Protocol):\n"
        "    async def fetch(self) -> str: ...\n\n"
        "async def fetch() -> str:\n"
        "    return 'ok'\n",
        encoding="utf-8",
    )
    (tmp_path / "tests/test_example.py").write_text(
        "from example import fetch\n\n"
        "class TestFetch:\n"
        "    async def test_fetch(self):\n"
        "        assert await fetch() == 'ok'\n\n"
        "async def test_fetch_module():\n"
        "    assert await fetch() == 'ok'\n",
        encoding="utf-8",
    )
    function_id = "python:src/example.py:fetch"
    test_id = "pytest:tests/test_example.py:TestFetch::test_fetch"
    module_test_id = "pytest:tests/test_example.py:test_fetch_module"

    index = PythonTestIndexBuilder(tmp_path).build(
        repository_id="example",
        generation=1,
        source_paths=("src/example.py",),
        test_paths=("tests/test_example.py",),
        bindings={function_id: (test_id, module_test_id)},
    )

    assert [item.function_id for item in index.functions] == [function_id]
    assert [item.test_id for item in index.tests] == sorted((test_id, module_test_id))
