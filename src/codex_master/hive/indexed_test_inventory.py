"""Static Python inventory adapter for Hive test-index V1."""

from __future__ import annotations

import ast
from collections import defaultdict
from collections.abc import Mapping, Sequence
import hashlib
from pathlib import Path, PurePosixPath

from codex_master.hive.indexed_tests import TestIndexError, TestIndexV1


_DEPENDENCY_POLICY = b"python-ast-v2:names,attributes,imports,module-bindings,static-calls,python-entrypoints"
_PYTHON_ENTRYPOINT_HEADERS = frozenset(
    {"#!/usr/bin/env python3", "#!/usr/bin/python3"}
)
_COOLDOWN_RANK = {
    "deterministic": 0,
    "integration": 1,
    "environmental": 2,
    "external": 3,
    "mandatory": 4,
}


def _digest(value: str | bytes) -> str:
    data = value.encode("utf-8") if isinstance(value, str) else value
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _repo_path(value: str) -> str:
    if not isinstance(value, str):
        raise TestIndexError("test.index_invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or ".." in path.parts or "." in path.parts:
        raise TestIndexError("test.index_invalid")
    return value


def _ast_digest(node: ast.AST) -> str:
    return _digest(ast.dump(node, annotate_fields=True, include_attributes=False))


class _FunctionVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.stack: list[str] = []
        self.type_only_stack: list[bool] = []
        self.functions: list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.stack.append(node.name)
        bases = {getattr(base, "id", getattr(base, "attr", "")) for base in node.bases}
        self.type_only_stack.append("Protocol" in bases)
        self.generic_visit(node)
        self.type_only_stack.pop()
        self.stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        decorators = {getattr(item, "id", getattr(item, "attr", "")) for item in node.decorator_list}
        if (self.type_only_stack and self.type_only_stack[-1]) or decorators & {"overload", "abstractmethod"}:
            return
        qualified = ".".join((*self.stack, node.name))
        self.functions.append((qualified, node))
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()


class _TestVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.class_name: str | None = None
        self.tests: list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        previous = self.class_name
        self.class_name = node.name
        for child in node.body:
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._record(child)
        self.class_name = previous

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._record(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._record(node)

    def _record(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        if not node.name.startswith("test"):
            return
        node_id = f"{self.class_name}::{node.name}" if self.class_name else node.name
        self.tests.append((node_id, node))


def _assertion_nodes(node: ast.AST) -> tuple[ast.AST, ...]:
    assertions: list[ast.AST] = []
    for child in ast.walk(node):
        if isinstance(child, ast.Assert):
            assertions.append(child)
            continue
        if not isinstance(child, ast.Call):
            continue
        function = child.func
        if isinstance(function, ast.Attribute):
            if function.attr.startswith("assert") or (
                isinstance(function.value, ast.Name)
                and function.value.id == "pytest"
                and function.attr in {"raises", "warns", "fail"}
            ):
                assertions.append(child)
    return tuple(assertions)


def _dependency_digest(node: ast.AST, module: ast.Module) -> str:
    names = {child.id for child in ast.walk(node) if isinstance(child, ast.Name)}
    rows = {
        f"name:{name}" for name in names
    } | {
        f"attribute:{child.attr}" for child in ast.walk(node) if isinstance(child, ast.Attribute)
    }
    for statement in module.body:
        if isinstance(statement, (ast.Import, ast.ImportFrom)):
            bound = {
                alias.asname or alias.name.split(".")[0]
                for alias in statement.names
            }
            if names & bound:
                rows.add("import:" + ast.dump(statement, include_attributes=False))
        elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
            targets = statement.targets if isinstance(statement, ast.Assign) else (statement.target,)
            bound = {
                child.id
                for target in targets
                for child in ast.walk(target)
                if isinstance(child, ast.Name)
            }
            if names & bound:
                rows.add("binding:" + ast.dump(statement, include_attributes=False))
    return _digest("\n".join(sorted(rows)))


class PythonTestIndexBuilder:
    """Build a strict index from Python AST and explicit function/test bindings."""

    def __init__(self, repository_root: Path) -> None:
        root = Path(repository_root)
        if not root.is_absolute() or not root.is_dir():
            raise TestIndexError("test.index_invalid")
        self._root = root.resolve()

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
        function_ids = set(functions)
        test_ids = set(tests)
        if set(bindings) != function_ids:
            raise TestIndexError("test.function_unindexed")
        normalized_bindings = {
            function_id: tuple(sorted(set(test_ids_for_function)))
            for function_id, test_ids_for_function in bindings.items()
        }
        if any(not values for values in normalized_bindings.values()):
            raise TestIndexError("test.function_unindexed")
        if any(not set(values) <= test_ids for values in normalized_bindings.values()):
            raise TestIndexError("test.test_uncollectable")
        covers: dict[str, list[str]] = defaultdict(list)
        for function_id, bound_tests in normalized_bindings.items():
            for test_id in bound_tests:
                covers[test_id].append(function_id)
        tests = {test_id: tests[test_id] for test_id in covers}
        function_meta = function_metadata or {}
        test_meta = test_metadata or {}
        function_entries = []
        for function_id in sorted(functions):
            path, qualified, node, module = functions[function_id]
            metadata = function_meta.get(function_id, {})
            function_entries.append(
                {
                    "function_id": function_id,
                    "language": "python",
                    "path": path,
                    "qualified_name": qualified,
                    "source_digest": _ast_digest(node),
                    "dependency_digest": _dependency_digest(node, module),
                    "test_ids": list(normalized_bindings[function_id]),
                    "cooldown_class": metadata.get("cooldown_class", "deterministic"),
                    "risk": metadata.get("risk", "read_only"),
                    "generated": metadata.get("generated", False),
                }
            )
        function_by_id = {entry["function_id"]: entry for entry in function_entries}
        test_entries = []
        for test_id in sorted(tests):
            path, node_id, node = tests[test_id]
            assertions = _assertion_nodes(node)
            if not assertions:
                raise TestIndexError("test.assertion_missing")
            strictest = max(
                (function_by_id[function_id]["cooldown_class"] for function_id in covers[test_id]),
                key=_COOLDOWN_RANK.__getitem__,
            )
            metadata = test_meta.get(test_id, {})
            test_entries.append(
                {
                    "test_id": test_id,
                    "runner": "pytest",
                    "path": path,
                    "node_id": node_id,
                    "test_digest": _ast_digest(node),
                    "assertion_digest": _digest(
                        "\n".join(ast.dump(item, include_attributes=False) for item in assertions)
                    ),
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
                "indexer_version": "python-ast-v2",
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
    ) -> dict[str, tuple[str, str, ast.FunctionDef | ast.AsyncFunctionDef, ast.Module]]:
        inventory: dict[str, tuple[str, str, ast.FunctionDef | ast.AsyncFunctionDef, ast.Module]] = {}
        for path in self._normalized_paths(paths):
            module = self._parse(path)
            visitor = _FunctionVisitor()
            visitor.visit(module)
            for qualified, node in visitor.functions:
                function_id = f"python:{path}:{qualified}"
                if function_id in inventory:
                    raise TestIndexError("test.index_invalid")
                inventory[function_id] = (path, qualified, node, module)
        if not inventory:
            raise TestIndexError("test.index_invalid")
        return inventory

    def _inventory_tests(
        self, paths: Sequence[str]
    ) -> dict[str, tuple[str, str, ast.FunctionDef | ast.AsyncFunctionDef]]:
        inventory: dict[str, tuple[str, str, ast.FunctionDef | ast.AsyncFunctionDef]] = {}
        for path in self._normalized_paths(paths):
            visitor = _TestVisitor()
            visitor.visit(self._parse(path))
            for node_id, node in visitor.tests:
                test_id = f"pytest:{path}:{node_id}"
                if test_id in inventory:
                    raise TestIndexError("test.index_invalid")
                inventory[test_id] = (path, node_id, node)
        if not inventory:
            raise TestIndexError("test.test_uncollectable")
        return inventory

    def _normalized_paths(self, paths: Sequence[str]) -> tuple[str, ...]:
        if not isinstance(paths, (list, tuple)) or not paths:
            raise TestIndexError("test.index_invalid")
        normalized = tuple(_repo_path(path) for path in paths)
        if tuple(sorted(set(normalized))) != normalized:
            raise TestIndexError("test.index_invalid")
        return normalized

    def _parse(self, relative_path: str) -> ast.Module:
        target = self._root / relative_path
        try:
            resolved = target.resolve(strict=True)
            resolved.relative_to(self._root)
            if not resolved.is_file():
                raise TestIndexError("test.index_invalid")
            source = resolved.read_text(encoding="utf-8")
            if resolved.suffix != ".py" and (
                not resolved.stat().st_mode & 0o111
                or source.partition("\n")[0] not in _PYTHON_ENTRYPOINT_HEADERS
            ):
                raise TestIndexError("test.index_invalid")
            return ast.parse(source, filename=relative_path)
        except (OSError, UnicodeError, SyntaxError, ValueError):
            raise TestIndexError("test.index_invalid") from None


__all__ = ["PythonTestIndexBuilder"]
