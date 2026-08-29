from __future__ import annotations

from pathlib import Path

from codex_master.hive.javascript_test_inventory import JavaScriptTestIndexBuilder


def test_javascript_builder_indexes_functions_methods_arrows_and_node_assertions(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "src/example.js").write_text(
        "export function add(left, right) { return left + right; }\n"
        "export const double = (value) => value * 2;\n"
        "export class Example { run(value) { return double(value); } }\n",
        encoding="utf-8",
    )
    (tmp_path / "tests/test-example.mjs").write_text(
        'import assert from "node:assert/strict";\n'
        'import test from "node:test";\n'
        'import { add, double, Example } from "../src/example.js";\n'
        'test("add contract", () => { assert.equal(add(1, 2), 3); });\n'
        'test("double contract", () => { assert.equal(double(2), 4); });\n'
        'test("method contract", () => { assert.equal(new Example().run(2), 4); });\n',
        encoding="utf-8",
    )
    ids = {
        "add": "javascript:src/example.js:add",
        "double": "javascript:src/example.js:double",
        "run": "javascript:src/example.js:Example.run",
    }
    tests = {
        "add": "node_test:tests/test-example.mjs:add contract",
        "double": "node_test:tests/test-example.mjs:double contract",
        "run": "node_test:tests/test-example.mjs:method contract",
    }

    index = JavaScriptTestIndexBuilder(tmp_path).build(
        repository_id="example",
        generation=1,
        source_paths=("src/example.js",),
        test_paths=("tests/test-example.mjs",),
        bindings={ids[name]: (tests[name],) for name in ids},
    )

    assert [item.function_id for item in index.functions] == sorted(ids.values())
    assert [item.test_id for item in index.tests] == sorted(tests.values())


def test_typescript_inventory_uses_pinned_grammar_and_stable_function_ids(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src/example.ts").write_text(
        "export function identity(value: number): number { return value; }\n",
        encoding="utf-8",
    )

    functions = JavaScriptTestIndexBuilder(tmp_path).source_function_ids(
        ("src/example.ts",)
    )

    assert functions == ("typescript:src/example.ts:identity",)
