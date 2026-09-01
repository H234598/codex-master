"""Pinned Tree-sitter JavaScript/TypeScript test-index adapter."""

from __future__ import annotations

import ast
from collections import defaultdict
from collections.abc import Mapping, Sequence
import json
from pathlib import Path

from tree_sitter import Language, Node, Parser
import tree_sitter_javascript
import tree_sitter_typescript

from codex_master.hive.indexed_test_inventory import _COOLDOWN_RANK, _digest, _repo_path
from codex_master.hive.indexed_tests import TestIndexError, TestIndexV1


_DEPENDENCY_POLICY = b"tree-sitter-js-ts-v1:identifiers,properties,static-calls"
_FUNCTION_TYPES = frozenset(
    {
        "function_declaration",
        "generator_function_declaration",
        "function_expression",
        "generator_function",
        "arrow_function",
        "method_definition",
    }
)


def _language(path: str) -> tuple[str, Language]:
    suffix = Path(path).suffix
    if suffix in {".js", ".mjs", ".cjs", ".jsx"}:
        return "javascript", Language(tree_sitter_javascript.language())
    if suffix in {".ts", ".tsx", ".mts", ".cts"}:
        capsule = (
            tree_sitter_typescript.language_tsx()
            if suffix == ".tsx"
            else tree_sitter_typescript.language_typescript()
        )
        return "typescript", Language(capsule)
    raise TestIndexError("test.index_invalid")


def _node_text(node: Node | None) -> str:
    if node is None:
        return ""
    try:
        return node.text.decode("utf-8")
    except UnicodeError:
        raise TestIndexError("test.index_invalid") from None


def _container_name(node: Node) -> str | None:
    current = node.parent
    while current is not None and current.type != "program":
        if current.type == "class_declaration":
            name = _node_text(current.child_by_field_name("name"))
            if name:
                return name
        if current.type == "object":
            parent = current.parent
            if parent is not None and parent.type in {"assignment_expression", "variable_declarator"}:
                field = "left" if parent.type == "assignment_expression" else "name"
                name = _node_text(parent.child_by_field_name(field))
                if name:
                    return name
        current = current.parent
    return None


def _assigned_name(node: Node) -> str | None:
    parent = node.parent
    if parent is None:
        return None
    if parent.type == "variable_declarator":
        return _node_text(parent.child_by_field_name("name")) or None
    if parent.type == "assignment_expression":
        return _node_text(parent.child_by_field_name("left")) or None
    if parent.type in {"pair", "pair_pattern"}:
        return _node_text(parent.child_by_field_name("key")) or None
    return None


def _dependency_digest(node: Node) -> str:
    rows: set[str] = set()
    stack = [node]
    while stack:
        current = stack.pop()
        if current.type in {"identifier", "property_identifier", "private_property_identifier"}:
            rows.add(f"{current.type}:{_node_text(current)}")
        stack.extend(current.named_children)
    return _digest("\n".join(sorted(rows)))


def _assertion_digest(callback: Node) -> str:
    assertions: list[bytes] = []
    stack = [callback]
    while stack:
        current = stack.pop()
        if current.type == "call_expression":
            called = _node_text(current.child_by_field_name("function"))
            if called == "assert" or called.startswith("assert.") or ".assert" in called:
                assertions.append(current.text)
        stack.extend(current.named_children)
    if not assertions:
        raise TestIndexError("test.assertion_missing")
    return _digest(b"\n".join(assertions))


def _string_literal(node: Node) -> str:
    raw = _node_text(node)
    try:
        value = json.loads(raw) if raw.startswith('"') else ast.literal_eval(raw)
    except (ValueError, SyntaxError):
        raise TestIndexError("test.index_invalid") from None
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise TestIndexError("test.index_invalid")
    return value


class JavaScriptTestIndexBuilder:
    """Build strict JS/TS indexes from pinned grammars and explicit bindings."""

    def __init__(self, repository_root: Path) -> None:
        root = Path(repository_root)
        if not root.is_absolute() or not root.is_dir():
            raise TestIndexError("test.index_invalid")
        self._root = root.resolve()

    def source_function_ids(self, source_paths: Sequence[str]) -> tuple[str, ...]:
        return tuple(sorted(self._inventory_functions(source_paths)))

    def build(
        self,
        *,
        repository_id: str,
        generation: int,
        source_paths: Sequence[str],
        test_paths: Sequence[str],
        bindings: Mapping[str, Sequence[str]],
        function_metadata: Mapping[str, Mapping[str, object]] | None = None,
        test_metadata: Mapping[str, Mapping[str, object]] | None = None,
        gates: Sequence[Mapping[str, object]] = (),
    ) -> TestIndexV1:
        functions = self._inventory_functions(source_paths)
        tests = self._inventory_tests(test_paths)
        if set(bindings) != set(functions):
            raise TestIndexError("test.function_unindexed")
        normalized = {
            function_id: tuple(sorted(set(bound_tests)))
            for function_id, bound_tests in bindings.items()
        }
        if any(not values for values in normalized.values()):
            raise TestIndexError("test.function_unindexed")
        if any(not set(values) <= set(tests) for values in normalized.values()):
            raise TestIndexError("test.test_uncollectable")
        covers: dict[str, list[str]] = defaultdict(list)
        for function_id, test_ids in normalized.items():
            for test_id in test_ids:
                covers[test_id].append(function_id)
        tests = {test_id: tests[test_id] for test_id in covers}
        function_meta = function_metadata or {}
        test_meta = test_metadata or {}
        function_entries: list[dict[str, object]] = []
        for function_id in sorted(functions):
            path, language, qualified_name, node = functions[function_id]
            metadata = function_meta.get(function_id, {})
            function_entries.append(
                {
                    "function_id": function_id,
                    "language": language,
                    "path": path,
                    "qualified_name": qualified_name,
                    "source_digest": _digest(node.text),
                    "dependency_digest": _dependency_digest(node),
                    "test_ids": list(normalized[function_id]),
                    "cooldown_class": metadata.get("cooldown_class", "deterministic"),
                    "risk": metadata.get("risk", "read_only"),
                    "generated": metadata.get("generated", False),
                }
            )
        by_function = {entry["function_id"]: entry for entry in function_entries}
        test_entries: list[dict[str, object]] = []
        for test_id in sorted(tests):
            path, node_id, callback = tests[test_id]
            strictest = max(
                (by_function[function_id]["cooldown_class"] for function_id in covers[test_id]),
                key=_COOLDOWN_RANK.__getitem__,
            )
            metadata = test_meta.get(test_id, {})
            test_entries.append(
                {
                    "test_id": test_id,
                    "runner": "node_test",
                    "path": path,
                    "node_id": node_id,
                    "test_digest": _digest(callback.text),
                    "assertion_digest": _assertion_digest(callback),
                    "covers": sorted(covers[test_id]),
                    "kind": metadata.get("kind", "unit"),
                    "timeout_seconds": metadata.get("timeout_seconds", 60),
                    "hermeticity": metadata.get("hermeticity", "hermetic"),
                    "required_resources": metadata.get("required_resources", []),
                    "cooldown_class": strictest,
                }
            )
        source_rows = "\n".join(
            f"{entry['function_id']}:{entry['source_digest']}" for entry in function_entries
        )
        test_rows = "\n".join(
            f"{entry['test_id']}:{entry['test_digest']}:{entry['assertion_digest']}"
            for entry in test_entries
        )
        return TestIndexV1.from_mapping(
            {
                "schema_version": 1,
                "generation": generation,
                "repository_id": repository_id,
                "indexer_version": "tree-sitter-js-ts-v1",
                "source_root_digest": _digest(source_rows),
                "test_root_digest": _digest(test_rows),
                "dependency_policy_digest": _digest(_DEPENDENCY_POLICY),
                "functions": function_entries,
                "tests": test_entries,
                "gates": list(gates),
            }
        )

    def _inventory_functions(
        self, paths: Sequence[str]
    ) -> dict[str, tuple[str, str, str, Node]]:
        inventory: dict[str, tuple[str, str, str, Node]] = {}
        for path in self._paths(paths):
            language_name, root = self._parse(path)
            anonymous: dict[str, int] = defaultdict(int)

            def visit(node: Node, scope: str = "") -> None:
                if node.type in _FUNCTION_TYPES:
                    name = _node_text(node.child_by_field_name("name"))
                    if node.type == "method_definition":
                        container = _container_name(node) or scope
                        qualified = f"{container}.{name}" if container else name
                    else:
                        assigned = name or _assigned_name(node)
                        if assigned:
                            qualified = f"{scope}.{assigned}" if scope else assigned
                        else:
                            anonymous[scope] += 1
                            marker = f"<anonymous-{node.type}-{anonymous[scope]}>"
                            qualified = f"{scope}.{marker}" if scope else marker
                    if not qualified:
                        raise TestIndexError("test.index_invalid")
                    function_id = f"{language_name}:{path}:{qualified}"
                    if function_id in inventory:
                        raise TestIndexError("test.index_invalid")
                    inventory[function_id] = (path, language_name, qualified, node)
                    body = node.child_by_field_name("body")
                    if body is not None:
                        for child in body.named_children:
                            visit(child, qualified)
                    return
                for child in node.named_children:
                    visit(child, scope)

            visit(root)
        if not inventory:
            raise TestIndexError("test.index_invalid")
        return inventory

    def _inventory_tests(self, paths: Sequence[str]) -> dict[str, tuple[str, str, Node]]:
        inventory: dict[str, tuple[str, str, Node]] = {}
        for path in self._paths(paths):
            _, root = self._parse(path)
            stack = [root]
            while stack:
                node = stack.pop()
                if node.type == "call_expression":
                    called = _node_text(node.child_by_field_name("function"))
                    arguments = node.child_by_field_name("arguments")
                    named = arguments.named_children if arguments is not None else []
                    if called in {"test", "it"} and len(named) >= 2 and named[0].type == "string":
                        callback = named[1]
                        if callback.type not in {"arrow_function", "function_expression"}:
                            raise TestIndexError("test.test_uncollectable")
                        node_id = _string_literal(named[0])
                        test_id = f"node_test:{path}:{node_id}"
                        if test_id in inventory:
                            raise TestIndexError("test.index_invalid")
                        inventory[test_id] = (path, node_id, callback)
                stack.extend(node.named_children)
        if not inventory:
            raise TestIndexError("test.test_uncollectable")
        return inventory

    def _paths(self, paths: Sequence[str]) -> tuple[str, ...]:
        if not isinstance(paths, (list, tuple)) or not paths:
            raise TestIndexError("test.index_invalid")
        normalized = tuple(_repo_path(path) for path in paths)
        if normalized != tuple(sorted(set(normalized))):
            raise TestIndexError("test.index_invalid")
        return normalized

    def _parse(self, path: str) -> tuple[str, Node]:
        target = (self._root / path).resolve(strict=True)
        try:
            target.relative_to(self._root)
        except ValueError:
            raise TestIndexError("test.index_invalid") from None
        if not target.is_file():
            raise TestIndexError("test.index_invalid")
        language_name, language = _language(path)
        try:
            tree = Parser(language).parse(target.read_bytes())
        except OSError:
            raise TestIndexError("test.index_invalid") from None
        if tree.root_node.has_error:
            raise TestIndexError("test.index_invalid")
        return language_name, tree.root_node


__all__ = ["JavaScriptTestIndexBuilder"]
